use {
    crate::{
        policy::Overwrite,
        secret::SecretBytes,
    },
    anyhow::{
        Context,
        Result,
    },
    std::{
        fs::{
            self,
            OpenOptions,
        },
        io::Write,
        path::{
            Path,
            PathBuf,
        },
    },
    uuid::Uuid,
};

/// One share file ready to publish. The bytes are cleared when this value is
/// dropped.
pub(crate) struct ShareOutput {
    path: PathBuf,
    bytes: SecretBytes,
}

impl ShareOutput {
    pub(crate) fn new(path: PathBuf, bytes: SecretBytes) -> Self {
        Self { path, bytes }
    }
}

/// Writes share files without clobbering, and rolls a partial set back if a
/// later write fails.
pub(crate) struct SharePublisher;

impl SharePublisher {
    pub(crate) fn ensure_available<'a>(paths: impl IntoIterator<Item=&'a Path>, overwrite: Overwrite) -> Result<()> {
        for path in paths {
            if path.is_dir() {
                anyhow::bail!("share path is a directory: {}", path.display());
            }
            if overwrite == Overwrite::Refuse && path.exists() {
                anyhow::bail!(
                    "Share file '{}' already exists. Use --force to overwrite it.",
                    path.display()
                );
            }
        }
        Ok(())
    }

    pub(crate) fn publish(files: &[ShareOutput], overwrite: Overwrite) -> Result<()> {
        let mut staged = Vec::with_capacity(files.len());
        let result = (|| -> Result<()> {
            for file in files {
                if file.path.is_dir() {
                    anyhow::bail!("share path is a directory: {}", file.path.display());
                }
                let tmp = temporary_path(&file.path)?;
                write_new_file(&tmp, file.bytes.as_slice())?;
                staged.push(StagedFile {
                    tmp,
                    dest: file.path.clone(),
                    backup: None,
                    published: false,
                });
            }
            if overwrite == Overwrite::Refuse {
                for stage in &staged {
                    if stage.dest.exists() {
                        anyhow::bail!(
                            "Share file '{}' already exists. Use --force to overwrite it.",
                            stage.dest.display()
                        );
                    }
                }
            }
            for stage in &mut staged {
                if stage.dest.exists() {
                    let backup = temporary_path(&stage.dest)?;
                    fs::rename(&stage.dest, &backup).with_context(|| {
                        format!(
                            "Failed to preserve existing share before replace: {}",
                            stage.dest.display()
                        )
                    })?;
                    stage.backup = Some(backup);
                }
                publish_temp(&stage.tmp, &stage.dest, stage.backup.is_some())?;
                stage.published = true;
            }
            Ok(())
        })();

        if result.is_err() {
            rollback(&staged);
            return result;
        }
        cleanup_success(&staged)?;
        for stage in &staged {
            sync_parent(&stage.dest);
        }
        Ok(())
    }
}

struct StagedFile {
    tmp: PathBuf,
    dest: PathBuf,
    backup: Option<PathBuf>,
    published: bool,
}

fn publish_temp(tmp: &Path, dest: &Path, replacing: bool) -> Result<()> {
    if replacing {
        // Destination was moved aside, so rename is an atomic create.
        fs::rename(tmp, dest).with_context(|| format!("Failed to replace share file: {}", dest.display()))?;
        return Ok(());
    }
    // hard_link fails if dest appeared after the exists check, without following a
    // final symlink.
    fs::hard_link(tmp, dest).with_context(|| format!("Failed to create share file: {}", dest.display()))?;
    let _ = fs::remove_file(tmp);
    Ok(())
}

fn rollback(staged: &[StagedFile]) {
    for stage in staged.iter().rev() {
        if stage.published {
            let _ = fs::remove_file(&stage.dest);
        }
        if let Some(backup) = &stage.backup {
            let _ = fs::rename(backup, &stage.dest);
        }
        let _ = fs::remove_file(&stage.tmp);
    }
}

fn cleanup_success(staged: &[StagedFile]) -> Result<()> {
    let mut leftovers = Vec::new();
    for stage in staged {
        if let Some(backup) = &stage.backup {
            // Unlink only. Opening the backup to overwrite it would follow a swapped
            // symlink.
            if let Err(err) = fs::remove_file(backup) {
                leftovers.push(format!("{}: {err}", backup.display()));
            }
        }
        let _ = fs::remove_file(&stage.tmp);
    }
    if leftovers.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "shares were written, but replaced file backups could not be removed: {}",
        leftovers.join("; ")
    )
}

fn temporary_path(dest: &Path) -> Result<PathBuf> {
    let parent = match dest.parent() {
        | Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        | _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent).with_context(|| format!("Failed to create directories for {}", dest.display()))?;
    Ok(parent.join(format!(".{}.tmp", Uuid::new_v4())))
}

fn write_new_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // mode() is masked by umask; set_permissions below is the actual restriction.
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("Failed to open temporary share file: {}", path.display()))?;
    restrict(&file, path)?;
    file.write_all(data)
        .with_context(|| format!("Failed to write share file: {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush share file: {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set share file permissions: {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_file: &std::fs::File, _path: &Path) -> Result<()> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use {
        super::{
            ShareOutput,
            SharePublisher,
        },
        crate::{
            policy::Overwrite,
            secret::SecretBytes,
        },
        std::{
            fs,
            path::PathBuf,
        },
        uuid::Uuid,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("agree-store-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn output(path: PathBuf, text: &str) -> ShareOutput {
        ShareOutput::new(path, SecretBytes::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn refuses_to_replace_without_force_and_leaves_the_file() {
        let dir = TempDir::new();
        let path = dir.path().join("alice.share");
        fs::write(&path, b"existing").unwrap();
        let err = SharePublisher::publish(&[output(path.clone(), "new")], Overwrite::Refuse).unwrap_err();
        assert!(err.to_string().contains("--force"));
        assert_eq!(fs::read(&path).unwrap(), b"existing");
    }

    #[test]
    fn replace_removes_the_backup() {
        let dir = TempDir::new();
        let path = dir.path().join("alice.share");
        fs::write(&path, b"existing").unwrap();
        SharePublisher::publish(&[output(path.clone(), "new")], Overwrite::Replace).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("alice.share")]);
    }

    #[test]
    fn failed_second_publish_rolls_back_the_first() {
        let dir = TempDir::new();
        let first = dir.path().join("alice.share");
        let blocker = dir.path().join("not-a-directory");
        fs::write(&blocker, b"x").unwrap();
        let second = blocker.join("bob.share");
        let err = SharePublisher::publish(
            &[output(first.clone(), "alice"), output(second, "bob")],
            Overwrite::Refuse,
        )
        .unwrap_err();
        assert!(!first.exists(), "{err}");
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            !name.to_string_lossy().contains(".tmp")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn new_share_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let path = dir.path().join("alice.share");
        SharePublisher::publish(&[output(path.clone(), "secret")], Overwrite::Refuse).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
