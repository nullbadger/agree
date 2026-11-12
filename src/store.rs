//! Writes secret bytes to a file or straight to a device node.
//!
//! File writes are created mode `0600` and published by rename. A device write
//! opens the existing node and writes the bytes from offset zero. The format is
//! self-delimiting, so leftover bytes after the payload are ignored on read.

use {
    crate::error::Error,
    anyhow::{
        Context,
        Result,
    },
    std::{
        fs::{
            self,
            File,
            OpenOptions,
        },
        io::{
            self,
            Write,
        },
        path::{
            Path,
            PathBuf,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Overwrite {
    Refuse,
    Replace,
}

impl Overwrite {
    pub(crate) fn from_flag(force: bool) -> Self {
        if force {
            Self::Replace
        } else {
            Self::Refuse
        }
    }
}

pub(crate) struct FilePublisher;

impl FilePublisher {
    pub(crate) fn ensure_available(path: &Path, overwrite: Overwrite) -> Result<()> {
        if path.is_dir() {
            anyhow::bail!("path is a directory: {}", path.display());
        }
        if overwrite == Overwrite::Refuse && path.exists() {
            anyhow::bail!("'{}' already exists. Use --force to overwrite it.", path.display());
        }
        Ok(())
    }

    pub(crate) fn publish(path: &Path, bytes: &[u8], overwrite: Overwrite) -> Result<()> {
        Self::ensure_available(path, overwrite)?;
        let tmp = temporary_path(path)?;
        write_new_file(&tmp, bytes)?;
        if overwrite == Overwrite::Replace && path.exists() {
            let backup = temporary_path(path)?;
            fs::rename(path, &backup).with_context(|| format!("Failed to preserve {}", path.display()))?;
            if let Err(err) = fs::rename(&tmp, path) {
                let _ = fs::rename(&backup, path);
                let _ = fs::remove_file(&tmp);
                return Err(err).with_context(|| format!("Failed to replace {}", path.display()));
            }
            let _ = fs::remove_file(&backup);
        } else if let Err(err) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("Failed to create {}", path.display()));
        }
        sync_parent(path);
        Ok(())
    }

    pub(crate) fn publish_from(path: &Path, source: &Path, overwrite: Overwrite) -> Result<()> {
        Self::ensure_available(path, overwrite)?;
        let tmp = temporary_path(path)?;
        copy_new_file(source, &tmp)?;
        if overwrite == Overwrite::Replace && path.exists() {
            let backup = temporary_path(path)?;
            fs::rename(path, &backup).with_context(|| format!("Failed to preserve {}", path.display()))?;
            if let Err(err) = fs::rename(&tmp, path) {
                let _ = fs::rename(&backup, path);
                let _ = fs::remove_file(&tmp);
                return Err(err).context("Failed to replace sealed secret");
            }
            let _ = fs::remove_file(&backup);
        } else if let Err(err) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(err).context("Failed to create sealed secret");
        }
        sync_parent(path);
        Ok(())
    }
}

pub(crate) struct DevicePublisher;

impl DevicePublisher {
    pub(crate) fn ensure_available(path: &Path, overwrite: Overwrite) -> Result<()> {
        if overwrite != Overwrite::Replace {
            return Err(Error::DeviceNeedsForce.into());
        }
        if !path.exists() {
            anyhow::bail!("device does not exist: {}", path.display());
        }
        let file = File::open(path).with_context(|| format!("Failed to open device {}", path.display()))?;
        if file.is_terminal() {
            return Err(Error::TerminalOutput.into());
        }
        Ok(())
    }

    pub(crate) fn publish(path: &Path, bytes: &[u8], overwrite: Overwrite) -> Result<()> {
        Self::ensure_available(path, overwrite)?;
        write_in_place(path, bytes)
    }

    pub(crate) fn publish_from(path: &Path, source: &Path, overwrite: Overwrite) -> Result<()> {
        Self::ensure_available(path, overwrite)?;
        let mut input = File::open(source).context("Failed to open staged secret")?;
        let mut output = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("Failed to open device {}", path.display()))?;
        if output.is_terminal() {
            return Err(Error::TerminalOutput.into());
        }
        io::copy(&mut input, &mut output).with_context(|| format!("Failed to write device {}", path.display()))?;
        output.sync_all().ok();
        Ok(())
    }
}

pub(crate) fn create_private_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    restrict(&file, path)?;
    Ok(file)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush {}", path.display()))?;
    Ok(())
}

fn copy_new_file(source: &Path, dest: &Path) -> Result<()> {
    let mut input = File::open(source).context("Failed to open staged secret")?;
    let mut output = create_private_file(dest)?;
    io::copy(&mut input, &mut output).context("Failed to copy staged secret")?;
    output.sync_all().context("Failed to flush staged secret")?;
    Ok(())
}

fn write_in_place(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to open device {}", path.display()))?;
    if file.is_terminal() {
        return Err(Error::TerminalOutput.into());
    }
    file.write_all(bytes)
        .with_context(|| format!("Failed to write device {}", path.display()))?;
    file.sync_all().ok();
    Ok(())
}

fn temporary_path(dest: &Path) -> Result<PathBuf> {
    let parent = match dest.parent() {
        | Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        | _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    let mut name = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut name);
    Ok(parent.join(format!(".agree-{}.tmp", crate::location::encode_hex(&name))))
}

#[cfg(unix)]
fn restrict(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}

trait IsTerminalFile {
    fn is_terminal(&self) -> bool;
}

impl IsTerminalFile for File {
    fn is_terminal(&self) -> bool {
        io::IsTerminal::is_terminal(self)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            DevicePublisher,
            FilePublisher,
            Overwrite,
        },
        std::{
            fs,
            os::unix::fs::PermissionsExt,
            path::PathBuf,
        },
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut name = [0u8; 8];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut name);
            let path = std::env::temp_dir().join(format!("agree-store-{}", crate::location::encode_hex(&name)));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_is_owner_only_and_device_prefix_writes_in_place() {
        let dir = TempDir::new();
        let path = dir.0.join("share.bin");
        FilePublisher::publish(&path, b"share", Overwrite::Refuse).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(FilePublisher::publish(&path, b"new", Overwrite::Refuse).is_err());

        let device = dir.0.join("node.bin");
        fs::write(&device, b"old-bytes-that-are-longer").unwrap();
        DevicePublisher::publish(&device, b"AGRS", Overwrite::Replace).unwrap();
        assert!(fs::read(&device).unwrap().starts_with(b"AGRS"));
        assert!(DevicePublisher::publish(&device, b"x", Overwrite::Refuse).is_err());
        assert!(DevicePublisher::publish(&dir.0.join("missing"), b"x", Overwrite::Replace).is_err());
        assert!(FilePublisher::ensure_available(&dir.0, Overwrite::Replace).is_err());
        FilePublisher::publish(&path, b"replaced", Overwrite::Replace).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replaced");
        let names: Vec<_> = fs::read_dir(&dir.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(names.is_empty(), "{names:?}");
    }
}
