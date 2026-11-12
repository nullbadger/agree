//! Hybrid encryption for an arbitrary-length secret.
//!
//! The secret is chunked under a data key. Only that key is split. The key is
//! either drawn here or supplied by the caller.
//! A share is therefore small enough for a YubiKey object, whatever the secret
//! length. Each chunk has its own nonce and binds the group, the policy, and
//! the chunk index, so a rearranged or swapped sealed file fails
//! authentication.

use {
    crate::{
        error::Error,
        memory::DataKey,
        secret::Password,
    },
    anyhow::{
        bail,
        Context,
        Result,
    },
    argon2::{
        Algorithm,
        Argon2,
        Params,
        Version,
    },
    chacha20poly1305::{
        aead::{
            Aead,
            KeyInit,
            Payload,
        },
        ChaCha20Poly1305,
        XChaCha20Poly1305,
        XNonce,
    },
    rand_core::{
        OsRng,
        RngCore,
    },
    std::{
        fs::File,
        io::{
            self,
            Read,
        },
        path::Path,
    },
    zeroize::Zeroize,
};

pub(crate) const KEY_LEN: usize = 32;
/// Longest data key `split` will generate. Each 32 bytes is one encryption
/// layer.
pub(crate) const MAX_KEY_LEN: usize = 32 * 32;
pub(crate) const NONCE_PREFIX_LEN: usize = 20;
pub(crate) const CHUNK_LEN: usize = 64 * 1024;
const SHARE_SALT_LEN: usize = 32;
const SHARE_NONCE_LEN: usize = 12;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// Encrypts and decrypts secret chunks under one data key.
pub(crate) struct SecretCipher {
    key: DataKey,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    group: [u8; 16],
    policy: Vec<u8>,
    key_bytes: u16,
}

impl SecretCipher {
    pub(crate) fn generate(group: [u8; 16], policy: &[u8], key_bytes: usize) -> Result<Self> {
        Ok(Self::from_key(DataKey::generate(key_bytes)?, group, policy))
    }

    pub(crate) fn from_key(key: DataKey, group: [u8; 16], policy: &[u8]) -> Self {
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        OsRng.fill_bytes(&mut nonce_prefix);
        let key_bytes = u16::try_from(key.as_bytes().len()).expect("key size fits in u16");
        Self {
            key,
            nonce_prefix,
            group,
            policy: policy.to_vec(),
            key_bytes,
        }
    }

    pub(crate) fn open(key: DataKey, nonce_prefix: [u8; NONCE_PREFIX_LEN], group: [u8; 16], policy: &[u8]) -> Self {
        let key_bytes = u16::try_from(key.as_bytes().len()).expect("key size fits in u16");
        Self {
            key,
            nonce_prefix,
            group,
            policy: policy.to_vec(),
            key_bytes,
        }
    }

    pub(crate) fn nonce_prefix(&self) -> &[u8; NONCE_PREFIX_LEN] {
        &self.nonce_prefix
    }

    pub(crate) fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }

    pub(crate) fn encrypt_chunk(&self, counter: u32, last: bool, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut current = plaintext.to_vec();
        for (layer, key) in self.key.as_bytes().chunks(KEY_LEN).enumerate() {
            let cipher = XChaCha20Poly1305::new_from_slice(key).context("invalid data key")?;
            let nonce = XNonce::from(self.nonce(counter));
            let aad = self.aad(counter, last, u8::try_from(layer).expect("layer fits in u8"));
            current = cipher
                .encrypt(&nonce, Payload {
                    msg: &current,
                    aad: &aad,
                })
                .map_err(|_| Error::EncryptionFailed)?;
        }
        Ok(current)
    }

    pub(crate) fn decrypt_chunk(&self, counter: u32, last: bool, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let layers = self.key.as_bytes().chunks(KEY_LEN).collect::<Vec<_>>();
        let mut current = ciphertext.to_vec();
        for (layer, key) in layers.iter().enumerate().rev() {
            let cipher = XChaCha20Poly1305::new_from_slice(key).context("invalid data key")?;
            let nonce = XNonce::from(self.nonce(counter));
            let aad = self.aad(counter, last, u8::try_from(layer).expect("layer fits in u8"));
            current = cipher
                .decrypt(&nonce, Payload {
                    msg: &current,
                    aad: &aad,
                })
                .map_err(|_| Error::AuthenticationFailed)?;
        }
        Ok(current)
    }

    fn nonce(&self, counter: u32) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    fn aad(&self, counter: u32, last: bool, layer: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 16 + 2 + self.policy.len() + 1 + 4 + 1);
        aad.extend_from_slice(b"agree-sealed-v1");
        aad.extend_from_slice(&self.group);
        aad.extend_from_slice(&self.key_bytes.to_be_bytes());
        aad.extend_from_slice(&self.policy);
        aad.push(layer);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.push(u8::from(last));
        aad
    }
}

/// Accept a data-key size that this tool can split and use as encryption
/// layers.
pub(crate) fn validate_key_bytes(key_bytes: u16) -> Result<usize> {
    let len = usize::from(key_bytes);
    if !(KEY_LEN..=MAX_KEY_LEN).contains(&len) || !len.is_multiple_of(KEY_LEN) {
        bail!("key size must be a multiple of {KEY_LEN} between {KEY_LEN} and {MAX_KEY_LEN}");
    }
    Ok(len)
}

/// Read exactly `len` key bytes from a file or pipe.
///
/// Does not seek, and does not ask the filesystem how long the source is. A
/// process substitution is a pipe, so the only length check is to read `len`
/// bytes and then one more. EOF after `len` is success. Another byte, or a
/// short read, is a refusal. The buffer is wiped on failure.
pub(crate) fn read_key_file(path: &Path, len: usize) -> Result<DataKey> {
    let mut file = File::open(path).with_context(|| format!("Failed to open key file {}", path.display()))?;
    let mut buf = vec![0u8; len.saturating_add(1)];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            | Ok(0) => break,
            | Ok(n) => filled += n,
            | Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            | Err(err) => {
                buf.zeroize();
                return Err(err).with_context(|| format!("Failed to read key file {}", path.display()));
            },
        }
    }
    if filled < len {
        buf.zeroize();
        bail!(
            "key file {} must contain exactly {len} bytes, got {filled}",
            path.display()
        );
    }
    if filled > len {
        buf.zeroize();
        bail!("key file {} must contain exactly {len} bytes, got more", path.display());
    }
    buf.truncate(len);
    Ok(DataKey::from_bytes(buf)?)
}

/// Argon2id + ChaCha20-Poly1305 seal for one Shamir share.
pub(crate) struct ShareCipher {
    argon: Argon2<'static>,
}

impl ShareCipher {
    pub(crate) fn new() -> Self {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_PARALLELISM, Some(KEY_LEN))
            .expect("fixed Argon2id parameters are valid");
        Self {
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    pub(crate) fn seal(&self, plaintext: &[u8], password: &Password, aad: &[u8]) -> Result<Vec<u8>> {
        let mut salt = [0u8; SHARE_SALT_LEN];
        let mut nonce = [0u8; SHARE_NONCE_LEN];
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        self.derive(password, &salt, &mut key)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).context("invalid share key")?;
        let nonce = chacha20poly1305::Nonce::try_from(nonce.as_slice()).expect("nonce is 12 bytes");
        let encrypted = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| Error::EncryptionFailed)?;
        key.zeroize();
        let mut out = Vec::with_capacity(salt.len() + nonce.len() + encrypted.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub(crate) fn open(&self, blob: &[u8], password: &Password, aad: &[u8]) -> Result<Vec<u8>> {
        let min = SHARE_SALT_LEN + SHARE_NONCE_LEN + 16;
        if blob.len() < min {
            return Err(Error::DecryptionFailed.into());
        }
        let (salt, rest) = blob.split_at(SHARE_SALT_LEN);
        let (nonce, ciphertext) = rest.split_at(SHARE_NONCE_LEN);
        let mut key = [0u8; KEY_LEN];
        self.derive(password, salt, &mut key)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).context("invalid share key")?;
        let nonce = chacha20poly1305::Nonce::try_from(nonce).expect("nonce is 12 bytes");
        let opened = cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| Error::DecryptionFailed);
        key.zeroize();
        opened.map_err(Into::into)
    }

    fn derive(&self, password: &Password, salt: &[u8], key: &mut [u8; KEY_LEN]) -> Result<()> {
        self.argon
            .hash_password_into(password.as_bytes(), salt, key)
            .map_err(|err| anyhow::anyhow!("Failed to derive share key: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            read_key_file,
            SecretCipher,
            KEY_LEN,
        },
        std::{
            fs,
            io::Write,
            path::PathBuf,
            process::Command,
            thread,
        },
    };

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let mut name = [0u8; 8];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut name);
            let path = std::env::temp_dir().join(format!("agree-key-{}", hex(&name)));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn chunk_roundtrip_binds_the_last_flag() {
        let cipher = SecretCipher::generate([7u8; 16], &[3, 5], KEY_LEN).unwrap();
        let wide = SecretCipher::generate([7u8; 16], &[3, 5], KEY_LEN * 2).unwrap();
        let ct = wide.encrypt_chunk(1, false, b"layer").unwrap();
        assert_eq!(wide.decrypt_chunk(1, false, &ct).unwrap(), b"layer");
        assert!(wide.decrypt_chunk(1, true, &ct).is_err());
        let ct = cipher.encrypt_chunk(0, true, b"signing-key").unwrap();
        assert_eq!(cipher.decrypt_chunk(0, true, &ct).unwrap(), b"signing-key");
        assert!(cipher.decrypt_chunk(0, false, &ct).is_err());
    }

    #[test]
    fn key_file_requires_an_exact_length_and_a_pipe_does_not_need_a_size() {
        let dir = Temp::new();
        let exact: Vec<u8> = (0u8..64).collect();
        let file = dir.path("key.bin");
        fs::write(&file, &exact).unwrap();
        assert_eq!(read_key_file(&file, 64).unwrap().as_bytes(), exact.as_slice());

        fs::write(dir.path("short.bin"), &exact[..32]).unwrap();
        let err = read_key_file(&dir.path("short.bin"), 64).unwrap_err().to_string();
        assert!(err.contains("exactly 64 bytes, got 32"), "{err}");

        let mut long = exact.clone();
        long.extend_from_slice(&[1, 2, 3, 4, 5]);
        fs::write(dir.path("long.bin"), &long).unwrap();
        let err = read_key_file(&dir.path("long.bin"), 64).unwrap_err().to_string();
        assert!(err.contains("exactly 64 bytes, got more"), "{err}");
        assert!(!err.contains("got 65"), "{err}");

        let fifo = dir.path("key.pipe");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let fifo_writer = fifo.clone();
        let payload = exact.clone();
        let writer = thread::spawn(move || {
            let mut pipe = fs::OpenOptions::new().write(true).open(fifo_writer).unwrap();
            pipe.write_all(&payload).unwrap();
        });
        assert_eq!(read_key_file(&fifo, 64).unwrap().as_bytes(), exact.as_slice());
        writer.join().unwrap();
    }
}
