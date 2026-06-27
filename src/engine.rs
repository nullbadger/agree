#[cfg(unix)]
use std::os::unix::fs::{
    OpenOptionsExt,
    PermissionsExt,
};
use {
    crate::{
        archive::{
            Archive,
            ArchiveData,
            AuthTag,
            Base64String,
            SecretInfo,
            Share,
            ShareInfo,
        },
        blueprint::{
            Blueprint,
            BlueprintShareEncryption,
        },
        error::Error,
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
    shamirs::{
        Share as ShamirShare,
        Sharks,
    },
    std::{
        collections::HashSet,
        fs,
        io::Write,
        path::{
            Path,
            PathBuf,
        },
    },
    uuid::Uuid,
    zeroize::Zeroize,
};

const AUTHENTICATED_V1_MAGIC: &[u8] = b"agree:authenticated:v1\0";
const AUTHENTICATED_V1_KEY_LEN: usize = 32;
const AUTHENTICATED_V1_NONCE_LEN: usize = 32;
const ENCRYPTION_SALT_LEN: usize = 32;
const ENCRYPTION_NONCE_LEN: usize = 12;
const ENCRYPTION_KEY_LEN: usize = 32;
const ENCRYPTION_TAG_LEN: usize = 16;
const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

type HmacSha512 = Hmac<sha2::Sha512>;

pub(crate) struct SecretSharingEngine {
    version: String,
    argon: Argon2<'static>,
}

impl SecretSharingEngine {
    pub(crate) fn new(version: String) -> Self {
        let params = Params::new(
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ENCRYPTION_KEY_LEN),
        )
        .expect("fixed Argon2id parameters are valid");
        Self {
            version,
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    pub(crate) fn generate(&self, secret_data: &[u8], blueprint: &Blueprint, trust: bool, force: bool) -> Result<()> {
        blueprint.validate()?;
        Self::preflight_share_outputs(blueprint, force)?;

        let (mut payload, auth) = self.encode_secret_payload(secret_data)?;
        let sharks = Sharks(u8::try_from(blueprint.threshold).context("Threshold is too large")?);
        let shares = sharks
            .dealer(&payload)
            .take(blueprint.generate.len())
            .collect::<Vec<_>>();
        payload.zeroize();

        if shares.len() != blueprint.generate.len() {
            anyhow::bail!(
                "Share generation returned {} shares for {} requested outputs",
                shares.len(),
                blueprint.generate.len()
            );
        }

        let pid = Uuid::new_v4().hyphenated().to_string();
        let mut archives = Vec::<(PathBuf, Archive)>::with_capacity(blueprint.generate.len());
        for (share_blueprint, mut share) in blueprint.generate.iter().zip(shares) {
            let archive = (|| -> Result<Archive> {
                let mut share_bytes = Vec::<u8>::from(&share);
                let share = match &share_blueprint.encrypt {
                    | Some(enc) => self.lock(&share_bytes, enc, auth.clone(), trust),
                    | None => {
                        Ok(Share::Plain {
                            data: Base64String::new(&share_bytes),
                            auth: auth.clone(),
                        })
                    },
                };
                share_bytes.zeroize();
                let archive_data = ArchiveData {
                    share: share?,
                    info: ShareInfo {
                        comment: share_blueprint.comment.clone(),
                        secret: if share_blueprint.info.unwrap_or(false) {
                            Some(SecretInfo {
                                num_shares: blueprint.generate.len(),
                                threshold: blueprint.threshold,
                            })
                        } else {
                            None
                        },
                    },
                };

                Ok(Archive {
                    version: self.version.clone(),
                    uid: Uuid::new_v4().hyphenated().to_string(),
                    pid: pid.clone(),
                    data: Base64String::new(
                        serde_json::to_vec(&archive_data).context("Failed to serialize archive data")?,
                    ),
                })
            })();
            share.zeroize();
            archives.push((share_blueprint.path.clone(), archive?));
        }

        Self::preflight_share_outputs(blueprint, force)?;
        for (path, archive) in archives {
            Self::write_archive(&path, &archive, force)?;
        }

        Ok(())
    }

    pub(crate) fn restore(&self, shares: &[(std::path::PathBuf, Vec<u8>)], interactive: bool) -> Result<Vec<u8>> {
        if shares.is_empty() {
            anyhow::bail!("At least one share is required");
        }

        let mut share_data = Vec::<ShamirShare>::with_capacity(shares.len());
        let mut groups = HashSet::<(String, AuthTag)>::new();
        let mut seen_uids = HashSet::<String>::new();
        let mut seen_share_indexes = HashSet::<u8>::new();
        let mut secret_info = Option::<SecretInfo>::None;
        let restored = (|| -> Result<Vec<u8>> {
            for (path, bytes) in shares {
                let archive = serde_json::from_slice::<Archive>(bytes)
                    .with_context(|| format!("Failed to parse share archive: {}", path.display()))?;
                self.validate_archive_version(&archive)?;
                if !seen_uids.insert(archive.uid.clone()) {
                    return Err(Error::DuplicateShare(path.display().to_string()).into());
                }

                let archive_data = archive
                    .decode_data()
                    .with_context(|| format!("Failed to decode share archive data: {}", path.display()))?;
                Self::validate_secret_info(&mut secret_info, archive_data.info.secret.as_ref())?;

                let (mut data, auth) = self.read_share_payload(archive_data.share, interactive)?;
                Self::validate_auth_tag(&auth)?;
                groups.insert((archive.pid.clone(), auth.clone()));

                let share_index = data
                    .first()
                    .copied()
                    .with_context(|| format!("Share payload is empty: {}", path.display()))?;
                if !seen_share_indexes.insert(share_index) {
                    data.zeroize();
                    return Err(Error::DuplicateShare(path.display().to_string()).into());
                }
                let share = ShamirShare::try_from(data.as_slice())
                    .map_err(|e| anyhow::anyhow!("Share payload has invalid format: {}: {}", path.display(), e))?;
                data.zeroize();
                share_data.push(share);
            }

            if groups.len() != 1 {
                return Err(Error::MismatchedShares.into());
            }
            if let Some(info) = &secret_info {
                if share_data.len() < info.threshold {
                    anyhow::bail!(
                        "Need at least {} shares to restore this secret; received {}",
                        info.threshold,
                        share_data.len()
                    );
                }
                if share_data.len() > info.num_shares {
                    anyhow::bail!(
                        "Received {} shares, but this secret only has {} generated shares",
                        share_data.len(),
                        info.num_shares
                    );
                }
            }

            let threshold = secret_info
                .as_ref()
                .map(|info| info.threshold)
                .unwrap_or(share_data.len());
            let sharks = Sharks(u8::try_from(threshold).context("Threshold is too large")?);
            let (_, auth) = groups.into_iter().next().ok_or(Error::MismatchedShares)?;
            let restored = sharks
                .recover(share_data.as_slice())
                .map_err(|e| anyhow::anyhow!("Failed to restore secret from shares: {}", e))?;
            self.verify_restored_secret(restored.to_vec(), &auth)
        })();
        share_data.zeroize();
        restored
    }

    pub(crate) fn info(&self, share: &[u8]) -> Result<Archive> {
        serde_json::from_slice::<Archive>(share).context("Failed to parse share archive")
    }

    pub(crate) fn validate_archive_version(&self, archive: &Archive) -> Result<()> {
        if archive.version != self.version {
            anyhow::bail!(
                "Unsupported archive version {}; this binary supports {}",
                archive.version,
                self.version
            );
        }
        Ok(())
    }

    pub(crate) fn lock(
        &self,
        plaintext: &[u8],
        enc: &BlueprintShareEncryption,
        auth: AuthTag,
        trust: bool,
    ) -> Result<Share> {
        let mut pass = enc.exec(trust).context("Failed to resolve share password")?;
        self.lock_with_password(plaintext, &mut pass, auth)
    }

    pub(crate) fn lock_with_password(&self, plaintext: &[u8], password: &mut String, auth: AuthTag) -> Result<Share> {
        let result = self.lock_resolved_password(plaintext, password, auth);
        password.zeroize();
        result
    }

    fn lock_resolved_password(&self, plaintext: &[u8], password: &str, auth: AuthTag) -> Result<Share> {
        let mut salt = [0u8; ENCRYPTION_SALT_LEN];
        let mut nonce = [0u8; ENCRYPTION_NONCE_LEN];
        let mut key = [0u8; ENCRYPTION_KEY_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let encrypted = (|| -> Result<Vec<u8>> {
            self.argon
                .hash_password_into(password.as_bytes(), &salt, &mut key)
                .map_err(|e| anyhow::anyhow!("Failed to derive encryption key: {}", e))?;
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Failed to initialize share cipher: {}", e))?;
            cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| Error::Decryption.into())
        })();
        key.zeroize();
        let encrypted = encrypted?;

        let mut data = Vec::with_capacity(salt.len() + nonce.len() + encrypted.len());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&encrypted);

        Ok(Share::Encrypted {
            data: Base64String::new(data),
            auth,
        })
    }

    fn decrypt_with_password(&self, data: &Base64String, password: &str) -> Result<Vec<u8>> {
        let encrypted = data.decode()?;
        let min_len = ENCRYPTION_SALT_LEN + ENCRYPTION_NONCE_LEN + ENCRYPTION_TAG_LEN;
        if encrypted.len() < min_len {
            return Err(Error::Decryption.into());
        }

        let (salt, rest) = encrypted.split_at(ENCRYPTION_SALT_LEN);
        let (nonce, ciphertext) = rest.split_at(ENCRYPTION_NONCE_LEN);
        let mut key = [0u8; ENCRYPTION_KEY_LEN];
        let result = (|| -> Result<Vec<u8>> {
            self.argon
                .hash_password_into(password.as_bytes(), salt, &mut key)
                .map_err(|e| anyhow::anyhow!("Failed to derive encryption key: {}", e))?;
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Failed to initialize share cipher: {}", e))?;
            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| Error::Decryption.into())
        })();
        key.zeroize();
        result
    }

    pub(crate) fn read_share_payload(&self, share: Share, interactive: bool) -> Result<(Vec<u8>, AuthTag)> {
        match share {
            | Share::Plain { data, auth } => Ok((data.decode()?, auth)),
            | Share::Encrypted { data, auth } => {
                if !interactive {
                    return Err(Error::NonInteractive.into());
                }

                Ok((self.unlock_interactive(&data)?, auth))
            },
        }
    }

    pub(crate) fn unlock_with_password(&self, data: &Base64String, password: &str) -> Result<Vec<u8>> {
        self.decrypt_with_password(data, password)
    }

    pub(crate) fn write_archive(path: &Path, archive: &Archive, overwrite: bool) -> Result<()> {
        let archive = serde_json::to_vec(archive).context("Failed to serialize share archive")?;
        Self::write_secret_file(path, &archive, overwrite)
    }

    fn encode_secret_payload(&self, secret_data: &[u8]) -> Result<(Vec<u8>, AuthTag)> {
        let mut key = [0u8; AUTHENTICATED_V1_KEY_LEN];
        let mut nonce = [0u8; AUTHENTICATED_V1_NONCE_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let tag = match self.authenticated_v1_tag(&key, &nonce, secret_data) {
            | Ok(tag) => tag,
            | Err(err) => {
                key.zeroize();
                return Err(err);
            },
        };
        let auth = AuthTag {
            nonce: Base64String::new(nonce),
            tag: Base64String::new(tag),
        };

        let mut payload = Vec::with_capacity(AUTHENTICATED_V1_MAGIC.len() + key.len() + secret_data.len());
        payload.extend_from_slice(AUTHENTICATED_V1_MAGIC);
        payload.extend_from_slice(&key);
        payload.extend_from_slice(secret_data);
        key.zeroize();
        Ok((payload, auth))
    }

    fn authenticated_v1_tag(&self, key: &[u8], nonce: &[u8], secret_data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key).context("Failed to initialize secret authenticator")?;
        mac.update(nonce);
        mac.update(AUTHENTICATED_V1_MAGIC);
        mac.update(self.version.as_bytes());
        mac.update(secret_data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify_authenticated_v1_tag(&self, key: &[u8], nonce: &[u8], secret_data: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key).context("Failed to initialize secret authenticator")?;
        mac.update(nonce);
        mac.update(AUTHENTICATED_V1_MAGIC);
        mac.update(self.version.as_bytes());
        mac.update(secret_data);
        mac.verify_slice(tag).map_err(|_| Error::AuthenticationFailed.into())
    }

    fn unlock_interactive(&self, data: &Base64String) -> Result<Vec<u8>> {
        let mut password: String = dialoguer::Password::new()
            .with_prompt("Enter password for share".to_owned())
            .interact()
            .context("Failed to read password")?;

        let result = self.unlock_with_password(data, &password);
        password.zeroize();
        result
    }

    fn validate_auth_tag(auth: &AuthTag) -> Result<()> {
        if auth.nonce.decode()?.len() != AUTHENTICATED_V1_NONCE_LEN || auth.tag.decode()?.len() != 64 {
            return Err(Error::AuthenticationFailed.into());
        }
        Ok(())
    }

    fn validate_secret_info(current: &mut Option<SecretInfo>, next: Option<&SecretInfo>) -> Result<()> {
        let Some(next) = next else {
            return Ok(());
        };

        match current {
            | Some(current) if current != next => Err(Error::MismatchedShares.into()),
            | Some(_) => Ok(()),
            | None => {
                *current = Some(next.clone());
                Ok(())
            },
        }
    }

    fn verify_restored_secret(&self, mut restored: Vec<u8>, auth: &AuthTag) -> Result<Vec<u8>> {
        if !restored.starts_with(AUTHENTICATED_V1_MAGIC) {
            restored.zeroize();
            return Err(Error::AuthenticationFailed.into());
        }
        let secret_offset = AUTHENTICATED_V1_MAGIC.len() + AUTHENTICATED_V1_KEY_LEN;
        if restored.len() < secret_offset {
            restored.zeroize();
            return Err(Error::AuthenticationFailed.into());
        }

        let nonce = match auth.nonce.decode() {
            | Ok(value) => value,
            | Err(err) => {
                restored.zeroize();
                return Err(err);
            },
        };
        let tag = match auth.tag.decode() {
            | Ok(value) => value,
            | Err(err) => {
                restored.zeroize();
                return Err(err);
            },
        };
        if nonce.len() != AUTHENTICATED_V1_NONCE_LEN {
            restored.zeroize();
            return Err(Error::AuthenticationFailed.into());
        }

        if let Err(err) = self.verify_authenticated_v1_tag(
            &restored[AUTHENTICATED_V1_MAGIC.len()..secret_offset],
            &nonce,
            &restored[secret_offset..],
            &tag,
        ) {
            restored.zeroize();
            return Err(err);
        }

        let secret = restored.split_off(secret_offset);
        restored.zeroize();
        Ok(secret)
    }

    fn preflight_share_outputs(blueprint: &Blueprint, overwrite: bool) -> Result<()> {
        if overwrite {
            return Ok(());
        }

        for share in &blueprint.generate {
            if share.path.exists() {
                anyhow::bail!(
                    "Share file '{}' already exists. Use --force to overwrite it.",
                    share.path.display()
                );
            }
        }
        Ok(())
    }

    fn write_secret_file(path: &Path, data: &[u8], overwrite: bool) -> Result<()> {
        if path.exists() && !overwrite {
            anyhow::bail!(
                "Share file '{}' already exists. Use --force to overwrite it.",
                path.display()
            );
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directories for {}", path.display()))?;
        }

        let tmp_path = Self::temporary_path_for(path)?;
        let result = (|| -> Result<()> {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);

            let mut file = opts
                .open(&tmp_path)
                .with_context(|| format!("Failed to open temporary share file: {}", tmp_path.display()))?;
            #[cfg(unix)]
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| format!("Failed to set share file permissions: {}", tmp_path.display()))?;
            file.write_all(data)
                .with_context(|| format!("Failed to write share file: {}", tmp_path.display()))?;
            file.sync_all()
                .with_context(|| format!("Failed to flush share file: {}", tmp_path.display()))?;

            if overwrite {
                Self::replace_file(&tmp_path, path)?;
                Self::sync_parent(path);
                Ok(())
            } else {
                fs::hard_link(&tmp_path, path)
                    .with_context(|| format!("Failed to create share file: {}", path.display()))?;
                // Cleanup is best-effort after the final path exists.
                let _ = fs::remove_file(&tmp_path);
                Self::sync_parent(path);
                Ok(())
            }
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }

        result
    }

    fn temporary_path_for(path: &Path) -> Result<PathBuf> {
        let file_name = path
            .file_name()
            .with_context(|| format!("Share path has no file name: {}", path.display()))?
            .to_string_lossy();
        let tmp_name = format!(".{}.{}.tmp", file_name, Uuid::new_v4());
        Ok(path.with_file_name(tmp_name))
    }

    #[cfg(unix)]
    fn sync_parent(path: &Path) {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }

    #[cfg(not(unix))]
    fn sync_parent(_path: &Path) {}

    #[cfg(not(windows))]
    fn replace_file(tmp_path: &Path, path: &Path) -> Result<()> {
        fs::rename(tmp_path, path).with_context(|| format!("Failed to replace share file: {}", path.display()))?;
        Ok(())
    }

    #[cfg(windows)]
    fn replace_file(tmp_path: &Path, path: &Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("Failed to remove share file before replace: {}", path.display()))?;
        }
        fs::rename(tmp_path, path).with_context(|| format!("Failed to replace share file: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::SecretSharingEngine,
        crate::{
            archive::{
                Archive,
                AuthTag,
                Base64String,
                Share,
            },
            blueprint::{
                Blueprint,
                BlueprintShare,
                BlueprintShareEncryption,
            },
        },
        anyhow::Result,
        shamirs::{
            Share as ShamirShare,
            Sharks,
        },
        std::{
            fs,
            path::{
                Path,
                PathBuf,
            },
        },
        uuid::Uuid,
    };

    const SECRET: &[u8] = b"correct horse battery staple";

    fn temp_dir() -> Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("agree-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn blueprint(dir: &Path) -> Blueprint {
        Blueprint {
            threshold: 2,
            generate: vec![
                BlueprintShare {
                    path: dir.join("alice.share"),
                    encrypt: None,
                    comment: None,
                    info: Some(true),
                },
                BlueprintShare {
                    path: dir.join("bob.share"),
                    encrypt: None,
                    comment: None,
                    info: Some(true),
                },
                BlueprintShare {
                    path: dir.join("charlie.share"),
                    encrypt: Some(BlueprintShareEncryption::Plain("charlie-password".to_string())),
                    comment: Some("encrypted share".to_string()),
                    info: Some(true),
                },
            ],
        }
    }

    fn read_archive(path: &Path) -> Result<Archive> {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn archive_with_auth(path: &Path, auth: AuthTag) -> Result<Vec<u8>> {
        let mut archive = read_archive(path)?;
        let mut data = archive.decode_data()?;
        match &mut data.share {
            | Share::Plain { auth: value, .. } | Share::Encrypted { auth: value, .. } => {
                *value = auth;
            },
        }
        archive.data = Base64String::new(serde_json::to_vec(&data)?);
        Ok(serde_json::to_vec(&archive)?)
    }

    #[test]
    fn restores_generated_plain_shares() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;
        let shares = vec![
            (
                blueprint.generate[0].path.clone(),
                fs::read(&blueprint.generate[0].path)?,
            ),
            (
                blueprint.generate[1].path.clone(),
                fs::read(&blueprint.generate[1].path)?,
            ),
        ];

        assert_eq!(engine.restore(&shares, false)?, SECRET);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn encrypted_share_contains_only_its_shamir_share() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;

        let alice_archive = engine.info(&fs::read(&blueprint.generate[0].path)?)?;
        let alice_data = alice_archive.decode_data()?;
        let alice_share = match alice_data.share {
            | Share::Plain { data, .. } => {
                ShamirShare::try_from(data.decode()?.as_slice()).map_err(|e| anyhow::anyhow!(e))?
            },
            | Share::Encrypted { .. } => unreachable!("alice share is not encrypted"),
        };

        let charlie_archive = engine.info(&fs::read(&blueprint.generate[2].path)?)?;
        let charlie_data = charlie_archive.decode_data()?;
        let (charlie_share, auth) = match charlie_data.share {
            | Share::Encrypted { data, auth } => {
                (
                    ShamirShare::try_from(engine.unlock_with_password(&data, "charlie-password")?.as_slice())
                        .map_err(|e| anyhow::anyhow!(e))?,
                    auth,
                )
            },
            | Share::Plain { .. } => unreachable!("charlie share is encrypted"),
        };

        assert_ne!(Vec::<u8>::from(&charlie_share), SECRET);
        let restored = Sharks(2)
            .recover([alice_share, charlie_share].iter())
            .map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(engine.verify_restored_secret(restored.to_vec(), &auth)?, SECRET);

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn authenticated_restore_rejects_tampered_tag() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;
        let alice = read_archive(&blueprint.generate[0].path)?;
        let alice_data = alice.decode_data()?;
        let auth = match alice_data.share {
            | Share::Plain {
                auth: AuthTag { nonce, .. },
                ..
            } => {
                AuthTag {
                    nonce,
                    tag: Base64String::new([0u8; 64]),
                }
            },
            | _ => unreachable!("alice share is plain and authenticated"),
        };
        let shares = vec![
            (
                blueprint.generate[0].path.clone(),
                archive_with_auth(&blueprint.generate[0].path, auth.clone())?,
            ),
            (
                blueprint.generate[1].path.clone(),
                archive_with_auth(&blueprint.generate[1].path, auth)?,
            ),
        ];

        assert!(engine.restore(&shares, false).is_err());
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn refuses_to_overwrite_existing_share_without_force() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);
        fs::write(&blueprint.generate[0].path, b"existing")?;

        assert!(engine.generate(SECRET, &blueprint, false, false).is_err());
        assert_eq!(fs::read(&blueprint.generate[0].path)?, b"existing");

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn provider_failure_does_not_write_partial_share_set() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let mut blueprint = blueprint(&dir);
        blueprint.generate[2].encrypt = Some(BlueprintShareEncryption::Shell("exit 1".to_string()));

        assert!(engine.generate(SECRET, &blueprint, true, false).is_err());
        for share in &blueprint.generate {
            assert!(!share.path.exists());
        }

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn rejects_legacy_checksum_shape() {
        let legacy = r#"
            {
              "share": {
                "plain": {
                  "data": "",
                  "checksum": "embedded_v1"
                }
              },
              "info": {}
            }
        "#;

        assert!(serde_json::from_str::<crate::archive::ArchiveData>(legacy).is_err());
    }

    #[test]
    fn encrypted_share_requires_interactive_restore_and_correct_password() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;
        let charlie = read_archive(&blueprint.generate[2].path)?;
        let charlie_data = charlie.decode_data()?;
        let Share::Encrypted { data, .. } = charlie_data.share else {
            unreachable!("charlie share is encrypted");
        };

        assert!(engine.unlock_with_password(&data, "wrong-password").is_err());
        let shares = vec![
            (
                blueprint.generate[0].path.clone(),
                fs::read(&blueprint.generate[0].path)?,
            ),
            (
                blueprint.generate[2].path.clone(),
                fs::read(&blueprint.generate[2].path)?,
            ),
        ];
        assert!(engine.restore(&shares, false).is_err());

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn redacted_info_hides_sensitive_archive_fields() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;
        let archive = read_archive(&blueprint.generate[2].path)?;
        let redacted = serde_json::to_string(&archive.decode_data()?.redacted_json())?;

        assert!(redacted.contains("<redacted>"));
        assert!(!redacted.contains("charlie-password"));
        assert!(!redacted.contains("argon2id"));

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn restore_rejects_unsupported_archive_version() -> Result<()> {
        let dir = temp_dir()?;
        let engine = SecretSharingEngine::new("0.0".to_string());
        let blueprint = blueprint(&dir);

        engine.generate(SECRET, &blueprint, false, false)?;
        let mut archive = read_archive(&blueprint.generate[0].path)?;
        archive.version = "9.9".to_owned();
        let shares = vec![
            (blueprint.generate[0].path.clone(), serde_json::to_vec(&archive)?),
            (
                blueprint.generate[1].path.clone(),
                fs::read(&blueprint.generate[1].path)?,
            ),
        ];

        assert!(engine.restore(&shares, false).is_err());
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
