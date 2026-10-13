use {
    crate::{
        archive::{
            Archive,
            ArchiveData,
            ArchiveVersion,
            AuthTag,
            GroupId,
            SecretInfo,
            Share,
            ShareBody,
            ShareFile,
            ShareInfo,
        },
        blueprint::Blueprint,
        crypto::{
            SecretAuthenticator,
            ShareCipher,
        },
        error::Error,
        policy::{
            Overwrite,
            PromptMode,
            ShellTrust,
        },
        prompt::PasswordPrompt,
        scheme::{
            ShareCount,
            Threshold,
        },
        secret::{
            Password,
            SecretBytes,
        },
        store::{
            ShareOutput,
            SharePublisher,
        },
    },
    anyhow::{
        Context,
        Result,
    },
    shamirs::{
        Share as ShamirShare,
        Sharks,
    },
    std::{
        collections::HashSet,
        path::Path,
    },
    zeroize::Zeroize,
};

/// Splits and restores secrets. Crypto, file publishing, and password prompts
/// stay in their own types.
pub(crate) struct SecretSharingEngine {
    version: ArchiveVersion,
    cipher: ShareCipher,
    authenticator: SecretAuthenticator,
}

impl SecretSharingEngine {
    pub(crate) fn new(version: ArchiveVersion) -> Self {
        Self {
            authenticator: SecretAuthenticator::new(&version),
            cipher: ShareCipher::new(),
            version,
        }
    }

    pub(crate) fn split(
        &self,
        secret: &SecretBytes,
        blueprint: &Blueprint,
        trust: ShellTrust,
        overwrite: Overwrite,
    ) -> Result<()> {
        blueprint.ensure_trust(trust)?;
        SharePublisher::ensure_available(blueprint.paths(), overwrite)?;
        let passwords = blueprint.resolve_passwords(trust)?;
        // A trusted provider can create an output path while it runs. Check again
        // before splitting.
        SharePublisher::ensure_available(blueprint.paths(), overwrite)?;

        let (auth, mut shamir_shares) = {
            let (payload, auth) = self.authenticator.seal(secret.as_slice())?;
            let shares = deal(&payload, blueprint.threshold(), blueprint.shares().len())?;
            (auth, shares)
        };
        let group = GroupId::new();
        let mut outputs = Vec::with_capacity(blueprint.shares().len());
        for ((share, password), shamir_share) in blueprint.shares().iter().zip(&passwords).zip(&shamir_shares) {
            let share_bytes = SecretBytes::new(Vec::<u8>::from(shamir_share));
            let sealed = match password {
                | Some(password) => Share::encrypted(self.cipher.seal(share_bytes.as_slice(), password)?, auth.clone()),
                | None => Share::plain(share_bytes, auth.clone()),
            };
            let info = ShareInfo::new(
                share.comment().map(str::to_owned),
                if share.include_info() {
                    Some(blueprint.secret_info()?)
                } else {
                    None
                },
            );
            let archive = Archive::create(self.version, group, &ArchiveData::new(sealed, info))?;
            outputs.push(ShareOutput::new(
                share.path().to_path_buf(),
                SecretBytes::new(archive.to_vec()?),
            ));
        }
        shamir_shares.zeroize();
        SharePublisher::publish(&outputs, overwrite)
    }

    pub(crate) fn restore<P: PasswordPrompt>(
        &self,
        shares: &[ShareFile],
        mode: PromptMode,
        prompt: &mut P,
    ) -> Result<SecretBytes> {
        if shares.is_empty() {
            anyhow::bail!("At least one share is required");
        }
        if shares.len() > ShareCount::MAX {
            anyhow::bail!("too many shares: {} exceeds {}", shares.len(), ShareCount::MAX);
        }

        let mut shamir_shares = Vec::with_capacity(shares.len());
        let mut seen_uids = HashSet::new();
        let mut seen_indexes = HashSet::new();
        let mut secret_info = None;
        let mut expected = None;
        let restored = (|| -> Result<SecretBytes> {
            for file in shares {
                let archive = Archive::parse(file.bytes())
                    .with_context(|| format!("Failed to parse share archive: {}", file.path().display()))?;
                self.ensure_version(&archive, file.path())?;
                if !seen_uids.insert(archive.uid()) {
                    return Err(Error::DuplicateShare {
                        path: file.path().display().to_string(),
                    }
                    .into());
                }
                let (share, info) = archive
                    .archive_data()
                    .with_context(|| format!("Failed to decode share archive data: {}", file.path().display()))?
                    .into_parts();
                note_secret_info(&mut secret_info, info.secret(), file.path())?;
                let (payload, auth) = self.unlock(share, mode, prompt, file.path())?;
                match &expected {
                    | None => expected = Some((archive.group_id(), auth.clone())),
                    | Some((group, expected_auth)) if *group != archive.group_id() => {
                        anyhow::bail!("share {} was created in a different split", file.path().display());
                    },
                    | Some((_, expected_auth)) if expected_auth != &auth => {
                        anyhow::bail!(
                            "share {} has a different authentication tag than the other shares",
                            file.path().display()
                        );
                    },
                    | Some(_) => {},
                }
                let index = share_index(payload.as_slice())?;
                if !seen_indexes.insert(index) {
                    return Err(Error::DuplicateShare {
                        path: file.path().display().to_string(),
                    }
                    .into());
                }
                let shamir = ShamirShare::try_from(payload.as_slice()).map_err(|err| {
                    anyhow::anyhow!("Share payload has invalid format: {}: {err}", file.path().display())
                })?;
                shamir_shares.push(shamir);
            }

            let threshold = restore_threshold(secret_info, shamir_shares.len())?;
            let (_, auth) = expected.context("no shares were provided")?;
            let sharks = Sharks(threshold.get());
            let mut recovered = sharks
                .recover(shamir_shares.as_slice())
                .map_err(|err| anyhow::anyhow!("Failed to restore secret from shares: {err}"))?;
            let payload = SecretBytes::new(std::mem::take(&mut *recovered));
            self.authenticator.open(payload, &auth)
        })();
        shamir_shares.zeroize();
        restored
    }

    pub(crate) fn edit<P: PasswordPrompt>(
        &self,
        file: &ShareFile,
        new_password: Option<Password>,
        prompt: &mut P,
    ) -> Result<()> {
        let mut archive = Archive::parse(file.bytes())
            .with_context(|| format!("Failed to parse share archive: {}", file.path().display()))?;
        self.ensure_version(&archive, file.path())?;
        let (share, info) = archive.archive_data()?.into_parts();
        let (payload, auth) = self.unlock(share, PromptMode::Interactive, prompt, file.path())?;
        let resealed = match &new_password {
            | Some(password) => Share::encrypted(self.cipher.seal(payload.as_slice(), password)?, auth),
            | None => Share::plain(payload, auth),
        };
        archive.set_data(&ArchiveData::new(resealed, info))?;
        SharePublisher::publish(
            &[ShareOutput::new(
                file.path().to_path_buf(),
                SecretBytes::new(archive.to_vec()?),
            )],
            Overwrite::Replace,
        )
    }

    fn ensure_version(&self, archive: &Archive, path: &Path) -> Result<()> {
        if archive.version() != self.version {
            anyhow::bail!(
                "Unsupported archive version {} in {}; this binary supports {}",
                archive.version(),
                path.display(),
                self.version
            );
        }
        Ok(())
    }

    fn unlock<P: PasswordPrompt>(
        &self,
        share: Share,
        mode: PromptMode,
        prompt: &mut P,
        path: &Path,
    ) -> Result<(SecretBytes, AuthTag)> {
        match share.into_parts() {
            | (ShareBody::Plain(data), auth) => Ok((data, auth)),
            | (ShareBody::Encrypted(data), auth) => {
                if mode != PromptMode::Interactive {
                    return Err(Error::PasswordRequired.into());
                }
                let password = prompt.password(&format!("Enter password for {}", path.display()))?;
                let opened = self.cipher.open(data.as_slice(), &password)?;
                Ok((opened, auth))
            },
        }
    }
}

fn deal(payload: &SecretBytes, threshold: Threshold, count: usize) -> Result<Vec<ShamirShare>> {
    let shares: Vec<_> = Sharks(threshold.get()).dealer(payload.as_slice()).take(count).collect();
    if shares.len() != count {
        anyhow::bail!(
            "Share generation returned {} shares for {count} requested outputs",
            shares.len()
        );
    }
    Ok(shares)
}

fn share_index(bytes: &[u8]) -> Result<u8> {
    let index = *bytes.first().context("share payload is empty")?;
    if index == 0 {
        anyhow::bail!("share index 0 is not valid");
    }
    Ok(index)
}

fn note_secret_info(current: &mut Option<SecretInfo>, next: Option<SecretInfo>, path: &Path) -> Result<()> {
    let Some(next) = next else {
        return Ok(());
    };
    match current {
        | Some(current) if *current != next => {
            anyhow::bail!("share {} metadata does not match the other shares", path.display());
        },
        | Some(_) => Ok(()),
        | None => {
            *current = Some(next);
            Ok(())
        },
    }
}

fn restore_threshold(info: Option<SecretInfo>, received: usize) -> Result<Threshold> {
    let Some(info) = info else {
        return Threshold::new(received).context("invalid restore threshold");
    };
    if received < info.threshold().as_usize() {
        anyhow::bail!(
            "Need at least {} shares to restore this secret; received {received}",
            info.threshold().as_usize()
        );
    }
    if received > info.num_shares().get() {
        anyhow::bail!(
            "Received {received} shares, but this secret only has {} generated shares",
            info.num_shares().get()
        );
    }
    Ok(info.threshold())
}

#[cfg(test)]
mod tests {
    use {
        super::SecretSharingEngine,
        crate::{
            archive::{
                Archive,
                ArchiveVersion,
            },
            blueprint::{
                Blueprint,
                BlueprintShareEncryption,
                ShareSpec,
            },
            paths::PathResolver,
            policy::{
                Overwrite,
                PromptMode,
                ShellTrust,
            },
            prompt::PasswordPrompt,
            secret::{
                Password,
                SecretBytes,
            },
        },
        anyhow::{
            Context,
            Result,
        },
        base64::{
            engine::general_purpose::STANDARD,
            Engine,
        },
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

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Result<Self> {
            let path = std::env::temp_dir().join(format!("agree-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ScriptedPrompt {
        passwords: Vec<Password>,
    }

    impl PasswordPrompt for ScriptedPrompt {
        fn password(&mut self, _: &str) -> Result<Password> {
            if self.passwords.is_empty() {
                anyhow::bail!("no scripted password");
            }
            Ok(self.passwords.remove(0))
        }
    }

    fn engine() -> SecretSharingEngine {
        SecretSharingEngine::new(ArchiveVersion::current())
    }

    fn secret() -> SecretBytes {
        SecretBytes::new(SECRET.to_vec())
    }

    fn paths(dir: &Path) -> PathResolver {
        PathResolver::with_cwd(dir.to_path_buf())
    }

    fn spec(path: PathBuf, password: Option<&str>, comment: Option<&str>, include_info: bool) -> ShareSpec {
        ShareSpec {
            path,
            encrypt: password.map(|password| {
                BlueprintShareEncryption::plain(Password::new(password.to_owned()).expect("test password"))
            }),
            comment: comment.map(str::to_owned),
            include_info,
        }
    }

    fn blueprint(dir: &Path) -> Blueprint {
        Blueprint::try_new(
            2,
            vec![
                spec(dir.join("alice.share"), None, None, true),
                spec(dir.join("bob.share"), None, None, true),
                spec(
                    dir.join("charlie.share"),
                    Some("charlie-password"),
                    Some("encrypted share"),
                    true,
                ),
            ],
            &paths(dir),
        )
        .expect("test blueprint")
    }

    fn read_share(path: &Path) -> Result<crate::archive::ShareFile> {
        Ok(crate::archive::ShareFile::new(path.to_path_buf(), fs::read(path)?))
    }

    fn restore(engine: &SecretSharingEngine, paths: &[PathBuf], mode: PromptMode) -> Result<SecretBytes> {
        let shares = paths.iter().map(|path| read_share(path)).collect::<Result<Vec<_>>>()?;
        engine.restore(&shares, mode, &mut ScriptedPrompt { passwords: Vec::new() })
    }

    #[test]
    fn restores_generated_plain_shares() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let restored = restore(
            &engine,
            &[
                blueprint.shares()[0].path().to_path_buf(),
                blueprint.shares()[1].path().to_path_buf(),
            ],
            PromptMode::Batch,
        )?;
        assert_eq!(restored.as_slice(), SECRET);
        Ok(())
    }

    #[test]
    fn generated_shares_default_to_threshold_info() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = Blueprint::from_hocon(
            br#"
                threshold = 2
                generate = [
                  { path = "alice.share" },
                  { path = "bob.share" }
                ]
            "#,
            &paths(&dir.0),
        )?;
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let err = restore(
            &engine,
            &[blueprint.shares()[0].path().to_path_buf()],
            PromptMode::Batch,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Need at least 2 shares"));
        Ok(())
    }

    #[test]
    fn encrypted_share_contains_only_its_shamir_share() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;

        let alice = Archive::parse(&fs::read(blueprint.shares()[0].path())?)?.archive_data()?;
        let alice_share = match alice.into_parts().0.into_parts() {
            | (crate::archive::ShareBody::Plain(data), _) => {
                ShamirShare::try_from(data.as_slice()).map_err(|err| anyhow::anyhow!(err))?
            },
            | _ => unreachable!("alice share is not encrypted"),
        };
        let charlie = Archive::parse(&fs::read(blueprint.shares()[2].path())?)?.archive_data()?;
        let (charlie_share, auth) = match charlie.into_parts().0.into_parts() {
            | (crate::archive::ShareBody::Encrypted(data), auth) => {
                let opened = engine
                    .cipher
                    .open(data.as_slice(), &Password::new("charlie-password".to_owned())?)?;
                (
                    ShamirShare::try_from(opened.as_slice()).map_err(|err| anyhow::anyhow!(err))?,
                    auth,
                )
            },
            | _ => unreachable!("charlie share is encrypted"),
        };

        assert_ne!(Vec::<u8>::from(&charlie_share), SECRET);
        let mut recovered = Sharks(2)
            .recover([alice_share, charlie_share].iter())
            .map_err(|err| anyhow::anyhow!(err))?;
        let payload = SecretBytes::new(std::mem::take(&mut *recovered));
        assert_eq!(engine.authenticator.open(payload, &auth)?.as_slice(), SECRET);
        Ok(())
    }

    #[test]
    fn authenticated_restore_rejects_tampered_tag() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        tamper_tag(blueprint.shares()[0].path())?;
        tamper_tag(blueprint.shares()[1].path())?;
        let shares = vec![
            read_share(blueprint.shares()[0].path())?,
            read_share(blueprint.shares()[1].path())?,
        ];
        assert!(engine
            .restore(&shares, PromptMode::Batch, &mut ScriptedPrompt {
                passwords: Vec::new()
            })
            .is_err());
        Ok(())
    }

    fn tamper_tag(path: &Path) -> Result<PathBuf> {
        let mut archive: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let encoded = archive["data"].as_str().context("missing data")?.to_owned();
        let mut data: serde_json::Value = serde_json::from_slice(&STANDARD.decode(encoded)?)?;
        let share = data["share"].as_object_mut().context("missing share")?;
        let body = if share.contains_key("plain") {
            share.get_mut("plain")
        } else {
            share.get_mut("encrypted")
        }
        .context("missing share body")?;
        body["auth"]["tag"] = serde_json::Value::String(STANDARD.encode([0u8; 64]));
        archive["data"] = serde_json::Value::String(STANDARD.encode(serde_json::to_vec(&data)?));
        fs::write(path, serde_json::to_vec(&archive)?)?;
        Ok(path.to_path_buf())
    }

    #[test]
    fn refuses_to_overwrite_existing_share_without_force() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        fs::write(blueprint.shares()[0].path(), b"existing")?;
        assert!(engine
            .split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)
            .is_err());
        assert_eq!(fs::read(blueprint.shares()[0].path())?, b"existing");
        Ok(())
    }

    #[test]
    fn provider_failure_does_not_write_partial_share_set() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = Blueprint::try_new(
            2,
            vec![
                spec(dir.0.join("alice.share"), None, None, true),
                spec(dir.0.join("bob.share"), None, None, true),
                ShareSpec {
                    path: dir.0.join("charlie.share"),
                    encrypt: Some(BlueprintShareEncryption::shell("exit 1".to_owned())),
                    comment: None,
                    include_info: true,
                },
            ],
            &paths(&dir.0),
        )?;
        assert!(engine
            .split(&secret(), &blueprint, ShellTrust::Trusted, Overwrite::Refuse)
            .is_err());
        for share in blueprint.shares() {
            assert!(!share.path().exists());
        }
        Ok(())
    }

    #[test]
    fn shell_without_trust_writes_nothing() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = Blueprint::try_new(
            1,
            vec![ShareSpec {
                path: dir.0.join("alice.share"),
                encrypt: Some(BlueprintShareEncryption::shell("printf secret".to_owned())),
                comment: None,
                include_info: true,
            }],
            &paths(&dir.0),
        )?;
        let err = engine
            .split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)
            .unwrap_err();
        assert!(err.to_string().contains("--trust"));
        assert!(!blueprint.shares()[0].path().exists());
        Ok(())
    }

    #[test]
    fn encrypted_share_requires_interactive_restore_and_correct_password() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let charlie = Archive::parse(&fs::read(blueprint.shares()[2].path())?)?.archive_data()?;
        let crate::archive::ShareBody::Encrypted(data) = charlie.into_parts().0.into_parts().0 else {
            unreachable!("charlie share is encrypted");
        };
        assert!(engine
            .cipher
            .open(data.as_slice(), &Password::new("wrong-password".to_owned())?)
            .is_err());
        let err = restore(
            &engine,
            &[
                blueprint.shares()[0].path().to_path_buf(),
                blueprint.shares()[2].path().to_path_buf(),
            ],
            PromptMode::Batch,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--interactive"));

        let shares = vec![
            read_share(blueprint.shares()[0].path())?,
            read_share(blueprint.shares()[2].path())?,
        ];
        let restored = engine.restore(&shares, PromptMode::Interactive, &mut ScriptedPrompt {
            passwords: vec![Password::new("charlie-password".to_owned())?],
        })?;
        assert_eq!(restored.as_slice(), SECRET);
        Ok(())
    }

    #[test]
    fn redacted_info_hides_sensitive_archive_fields() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let archive = Archive::parse(&fs::read(blueprint.shares()[2].path())?)?;
        let redacted = serde_json::to_string(&archive.archive_data()?.redacted_json())?;
        let report = archive.report()?.to_string();
        assert!(redacted.contains("<redacted>"));
        assert!(report.contains("<redacted>"));
        assert!(!redacted.contains("charlie-password"));
        assert!(!report.contains("charlie-password"));
        assert!(!redacted.contains("argon2id"));
        Ok(())
    }

    #[test]
    fn restore_rejects_unsupported_archive_version() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = blueprint(dir.0.as_path());
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let mut value: serde_json::Value = serde_json::from_slice(&fs::read(blueprint.shares()[0].path())?)?;
        value["version"] = serde_json::json!("9.9");
        let shares = vec![
            crate::archive::ShareFile::new(blueprint.shares()[0].path().to_path_buf(), serde_json::to_vec(&value)?),
            read_share(blueprint.shares()[1].path())?,
        ];
        assert!(engine
            .restore(&shares, PromptMode::Batch, &mut ScriptedPrompt {
                passwords: Vec::new()
            })
            .is_err());
        Ok(())
    }

    #[test]
    fn restores_when_more_shares_than_threshold_are_supplied() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = Blueprint::try_new(
            2,
            vec![
                spec(dir.0.join("alice.share"), None, None, true),
                spec(dir.0.join("bob.share"), None, None, true),
                spec(dir.0.join("charlie.share"), None, None, true),
            ],
            &paths(&dir.0),
        )?;
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let restored = restore(
            &engine,
            &[
                blueprint.shares()[0].path().to_path_buf(),
                blueprint.shares()[1].path().to_path_buf(),
                blueprint.shares()[2].path().to_path_buf(),
            ],
            PromptMode::Batch,
        )?;
        assert_eq!(restored.as_slice(), SECRET);
        Ok(())
    }

    #[test]
    fn rejects_shares_from_different_splits() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let first = Blueprint::try_new(1, vec![spec(dir.0.join("one.share"), None, None, true)], &paths(&dir.0))?;
        let second = Blueprint::try_new(1, vec![spec(dir.0.join("two.share"), None, None, true)], &paths(&dir.0))?;
        engine.split(&secret(), &first, ShellTrust::Denied, Overwrite::Refuse)?;
        engine.split(&secret(), &second, ShellTrust::Denied, Overwrite::Refuse)?;
        let err = restore(
            &engine,
            &[
                first.shares()[0].path().to_path_buf(),
                second.shares()[0].path().to_path_buf(),
            ],
            PromptMode::Batch,
        )
        .unwrap_err();
        assert!(err.to_string().contains("different split"));
        Ok(())
    }

    #[test]
    fn edit_replaces_password_and_still_restores() -> Result<()> {
        let dir = TempDir::new()?;
        let engine = engine();
        let blueprint = Blueprint::try_new(
            2,
            vec![
                spec(dir.0.join("alice.share"), None, None, true),
                spec(dir.0.join("bob.share"), Some("old-password"), None, true),
            ],
            &paths(&dir.0),
        )?;
        engine.split(&secret(), &blueprint, ShellTrust::Denied, Overwrite::Refuse)?;
        let bob = read_share(blueprint.shares()[1].path())?;
        engine.edit(
            &bob,
            Some(Password::new("new-password".to_owned())?),
            &mut ScriptedPrompt {
                passwords: vec![Password::new("old-password".to_owned())?],
            },
        )?;
        let edited = Archive::parse(&fs::read(blueprint.shares()[1].path())?)?.archive_data()?;
        let crate::archive::ShareBody::Encrypted(data) = edited.into_parts().0.into_parts().0 else {
            unreachable!("edited share stays encrypted");
        };
        assert!(engine
            .cipher
            .open(data.as_slice(), &Password::new("old-password".to_owned())?)
            .is_err());
        let shares = vec![
            read_share(blueprint.shares()[0].path())?,
            read_share(blueprint.shares()[1].path())?,
        ];
        let restored = engine.restore(&shares, PromptMode::Interactive, &mut ScriptedPrompt {
            passwords: vec![Password::new("new-password".to_owned())?],
        })?;
        assert_eq!(restored.as_slice(), SECRET);
        Ok(())
    }

    #[test]
    fn rejects_share_index_zero() {
        assert!(super::share_index(&[0, 1]).is_err());
        assert_eq!(super::share_index(&[1, 2]).unwrap(), 1);
    }
}
