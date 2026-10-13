use {
    crate::{
        archive::{
            ArchiveVersion,
            AuthTag,
            AUTH_NONCE_LEN,
            AUTH_TAG_LEN,
        },
        error::Error,
        secret::{
            Password,
            SecretBytes,
        },
    },
    anyhow::{
        Context,
        Result,
    },
    argon2::{
        password_hash::rand_core::{
            OsRng,
            RngCore,
        },
        Algorithm,
        Argon2,
        Params,
        Version,
    },
    chacha20poly1305::{
        aead::{
            Aead,
            KeyInit,
        },
        ChaCha20Poly1305,
        Nonce,
    },
    hmac::{
        Hmac,
        Mac,
    },
    zeroize::{
        Zeroize,
        ZeroizeOnDrop,
    },
};

/// Payload layout, before Shamir splitting:
/// `magic || hmac_key || secret`.
///
/// The matching tag is `HMAC-SHA512(key, nonce || magic || version || secret)`.
/// The tag and nonce are stored in the archive, outside the split.
/// Fewer-than-threshold readers therefore see a tag but not a key they can
/// reuse. The version string is not length-prefixed; restore rejects other
/// versions before verification, so the concatenation is unambiguous for a
/// given binary.
const AUTHENTICATED_V1_MAGIC: &[u8] = b"agree:authenticated:v1\0";
const AUTHENTICATED_V1_KEY_LEN: usize = 32;

/// Encrypted share layout, before base64: `salt[32] || nonce[12] ||
/// ciphertext`.
const ENCRYPTION_SALT_LEN: usize = 32;
const ENCRYPTION_NONCE_LEN: usize = 12;
const ENCRYPTION_KEY_LEN: usize = 32;
const ENCRYPTION_TAG_LEN: usize = 16;
const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

type HmacSha512 = Hmac<sha2::Sha512>;

#[derive(Zeroize, ZeroizeOnDrop)]
struct Key32([u8; 32]);

/// Argon2id + ChaCha20-Poly1305 seal for one share payload.
pub(crate) struct ShareCipher {
    argon: Argon2<'static>,
}

impl ShareCipher {
    pub(crate) fn new() -> Self {
        let params = Params::new(
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ENCRYPTION_KEY_LEN),
        )
        .expect("fixed Argon2id parameters are valid");
        Self {
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    pub(crate) fn seal(&self, plaintext: &[u8], password: &Password) -> Result<SecretBytes> {
        let mut salt = [0u8; ENCRYPTION_SALT_LEN];
        let mut nonce = [0u8; ENCRYPTION_NONCE_LEN];
        let mut key = Key32([0u8; ENCRYPTION_KEY_LEN]);
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        self.argon
            .hash_password_into(password.as_bytes(), &salt, &mut key.0)
            .map_err(|err| anyhow::anyhow!("Failed to derive encryption key: {err}"))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
            .map_err(|err| anyhow::anyhow!("Failed to initialize share cipher: {err}"))?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionFailed)?;
        let mut data = Vec::with_capacity(salt.len() + nonce.len() + encrypted.len());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&encrypted);
        Ok(SecretBytes::new(data))
    }

    pub(crate) fn open(&self, blob: &[u8], password: &Password) -> Result<SecretBytes> {
        let parsed = EncryptedBlob::parse(blob)?;
        let mut key = Key32([0u8; ENCRYPTION_KEY_LEN]);
        self.argon
            .hash_password_into(password.as_bytes(), parsed.salt, &mut key.0)
            .map_err(|err| anyhow::anyhow!("Failed to derive encryption key: {err}"))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
            .map_err(|err| anyhow::anyhow!("Failed to initialize share cipher: {err}"))?;
        cipher
            .decrypt(Nonce::from_slice(parsed.nonce), parsed.ciphertext)
            .map(SecretBytes::new)
            .map_err(|_| Error::DecryptionFailed.into())
    }
}

struct EncryptedBlob<'a> {
    salt: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> EncryptedBlob<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let min_len = ENCRYPTION_SALT_LEN + ENCRYPTION_NONCE_LEN + ENCRYPTION_TAG_LEN;
        if data.len() < min_len {
            return Err(Error::DecryptionFailed.into());
        }
        let (salt, rest) = data.split_at(ENCRYPTION_SALT_LEN);
        let (nonce, ciphertext) = rest.split_at(ENCRYPTION_NONCE_LEN);
        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Builds and checks the authenticated secret payload that is split across
/// shares.
pub(crate) struct SecretAuthenticator {
    version: String,
}

impl SecretAuthenticator {
    pub(crate) fn new(version: &ArchiveVersion) -> Self {
        Self {
            version: version.to_string(),
        }
    }

    pub(crate) fn seal(&self, secret: &[u8]) -> Result<(SecretBytes, AuthTag)> {
        let mut key = Key32([0u8; AUTHENTICATED_V1_KEY_LEN]);
        let mut nonce = [0u8; AUTH_NONCE_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key.0);
        rng.fill_bytes(&mut nonce);
        let tag = self.tag(&key.0, &nonce, secret)?;
        let mut payload = Vec::with_capacity(AUTHENTICATED_V1_MAGIC.len() + key.0.len() + secret.len());
        payload.extend_from_slice(AUTHENTICATED_V1_MAGIC);
        payload.extend_from_slice(&key.0);
        payload.extend_from_slice(secret);
        Ok((SecretBytes::new(payload), AuthTag::new(nonce, tag)))
    }

    pub(crate) fn open(&self, mut restored: SecretBytes, auth: &AuthTag) -> Result<SecretBytes> {
        let secret_offset = AUTHENTICATED_V1_MAGIC.len() + AUTHENTICATED_V1_KEY_LEN;
        if restored.len() < secret_offset || !restored.as_slice().starts_with(AUTHENTICATED_V1_MAGIC) {
            return Err(Error::AuthenticationFailed.into());
        }
        self.verify(
            &restored.as_slice()[AUTHENTICATED_V1_MAGIC.len()..secret_offset],
            auth.nonce(),
            &restored.as_slice()[secret_offset..],
            auth.tag(),
        )?;
        Ok(restored.split_off(secret_offset))
    }

    fn tag(&self, key: &[u8], nonce: &[u8], secret: &[u8]) -> Result<[u8; AUTH_TAG_LEN]> {
        let mut mac = self.mac(key)?;
        mac.update(nonce);
        mac.update(AUTHENTICATED_V1_MAGIC);
        mac.update(self.version.as_bytes());
        mac.update(secret);
        let bytes = mac.finalize().into_bytes();
        bytes.as_slice().try_into().context("HMAC-SHA512 tag was not 64 bytes")
    }

    fn verify(&self, key: &[u8], nonce: &[u8], secret: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac = self.mac(key)?;
        mac.update(nonce);
        mac.update(AUTHENTICATED_V1_MAGIC);
        mac.update(self.version.as_bytes());
        mac.update(secret);
        mac.verify_slice(tag).map_err(|_| Error::AuthenticationFailed.into())
    }

    fn mac(&self, key: &[u8]) -> Result<HmacSha512> {
        <HmacSha512 as Mac>::new_from_slice(key).context("Failed to initialize secret authenticator")
    }
}
