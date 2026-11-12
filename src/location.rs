//! Destinations for shares and restored secrets.
//!
//! A share must name a protocol. `path=` is a file. `device=` writes the same
//! bytes straight to a hardware node. `yubi=` writes them to a PIV data object.
//! The separator is `=`. A sealed file or `--key-file` may still be a bare
//! path.

use {
    anyhow::{
        bail,
        Context,
        Result,
    },
    path_clean::PathClean,
    std::{
        env,
        fmt,
        path::{
            Path,
            PathBuf,
        },
    },
};

/// YubiKey 4/5 PIV object limit (`3072 - 9` byte message overhead).
pub(crate) const YUBIKEY_OBJECT_MAX: usize = 3063;
/// First object id that does not collide with certificates or admin data.
#[cfg(feature = "yubikey")]
pub(crate) const YUBIKEY_SAFE_MIN: u32 = 0x005f_ff20;
const YUBIKEY_MIN: u32 = 0x005f_0000;
const YUBIKEY_MAX: u32 = 0x005f_ffff;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Location {
    File(PathBuf),
    Device(PathBuf),
    YubiKey { serial: Option<u32>, object: u32 },
}

impl Location {
    pub(crate) fn is_yubikey(&self) -> bool {
        matches!(self, Self::YubiKey { .. })
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::File(path) => write!(f, "path={}", path.display()),
            | Self::Device(path) => write!(f, "device={}", path.display()),
            | Self::YubiKey {
                serial: Some(serial),
                object,
            } => write!(f, "yubi={serial}/{object:06x}"),
            | Self::YubiKey { serial: None, object } => write!(f, "yubi={object:06x}"),
        }
    }
}

/// Resolves locations once, at the process boundary.
#[derive(Clone, Debug)]
pub(crate) struct Locator {
    cwd: PathBuf,
    home: Option<PathBuf>,
}

impl Locator {
    pub(crate) fn from_process() -> Result<Self> {
        Ok(Self {
            cwd: env::current_dir().context("Failed to get current directory")?,
            home: env::var_os("HOME").map(PathBuf::from),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_cwd(cwd: PathBuf) -> Self {
        Self { cwd, home: None }
    }

    pub(crate) fn parse(&self, text: &str) -> Result<Location> {
        self.parse_location(text, false)
    }

    /// A share must name `path=`, `yubi=`, or `device=`. A bare path is not a
    /// share.
    pub(crate) fn parse_share(&self, text: &str) -> Result<Location> {
        self.parse_location(text, true)
    }

    fn parse_location(&self, text: &str, share: bool) -> Result<Location> {
        if text.starts_with("yubikey:") || text.starts_with("yubi:") || text.starts_with("device:") {
            bail!("location protocols use '=': path=, yubi=, or device=");
        }
        if let Some(rest) = text.strip_prefix("yubi=") {
            return parse_yubikey(rest);
        }
        if let Some(rest) = text.strip_prefix("device=") {
            if rest.is_empty() {
                bail!("device path must not be empty");
            }
            return Ok(Location::Device(self.resolve_path(Path::new(rest))?));
        }
        if let Some(rest) = text.strip_prefix("path=") {
            if rest.is_empty() {
                bail!("path must not be empty");
            }
            return Ok(Location::File(self.resolve_path(Path::new(rest))?));
        }
        if share {
            bail!("share must start with a protocol: path=, yubi=, or device=");
        }
        if text.is_empty() {
            bail!("path must not be empty");
        }
        Ok(Location::File(self.resolve_path(Path::new(text))?))
    }

    fn resolve_path(&self, path: &Path) -> Result<PathBuf> {
        let expanded = expand_tilde(path, self.home.as_deref())?;
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.join(expanded)
        };
        Ok(absolute.clean())
    }
}

fn parse_yubikey(text: &str) -> Result<Location> {
    let (serial, object_text) = match text.split_once('/') {
        | Some((serial, object)) => {
            if serial.is_empty() || object.is_empty() {
                bail!("yubi location must be yubi=[serial/]object");
            }
            let serial = serial.parse::<u32>().context("YubiKey serial is not a number")?;
            (Some(serial), object)
        },
        | None => (None, text),
    };
    let object = parse_object_id(object_text)?;
    Ok(Location::YubiKey { serial, object })
}

/// Pick the only attached key when a location omitted the serial.
pub(crate) fn resolve_unspecified_serial(attached: &[u32]) -> Result<u32> {
    match attached {
        | [] => bail!("no YubiKey detected"),
        | [serial] => Ok(*serial),
        | many => {
            let list = many.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
            bail!("multiple YubiKeys are attached ({list}); use yubi=SERIAL/object");
        },
    }
}

pub(crate) fn parse_object_id(text: &str) -> Result<u32> {
    if text.is_empty() || text.len() > 6 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("YubiKey object id must be 1 to 6 hex digits in the range 5f0000-5fffff");
    }
    let object = u32::from_str_radix(text, 16).context("invalid YubiKey object id")?;
    if !(YUBIKEY_MIN..=YUBIKEY_MAX).contains(&object) {
        bail!("YubiKey object id {object:06x} is outside 5f0000-5fffff");
    }
    Ok(object)
}

#[cfg(feature = "yubikey")]
pub(crate) fn ensure_object_allowed(object: u32, force: bool) -> Result<()> {
    use crate::error::Error;
    if object < YUBIKEY_SAFE_MIN && !force {
        return Err(Error::ReservedObject { object }.into());
    }
    Ok(())
}

fn expand_tilde(path: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let Some(text) = path.to_str() else {
        return Ok(path.to_path_buf());
    };
    if text == "~" {
        return home
            .context("cannot expand '~': HOME is not set")
            .map(Path::to_path_buf);
    }
    if let Some(rest) = text.strip_prefix("~/") {
        let home = home.context("cannot expand '~': HOME is not set")?;
        return Ok(home.join(rest));
    }
    Ok(path.to_path_buf())
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected hex");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        | b'0'..=b'9' => Ok(byte - b'0'),
        | b'a'..=b'f' => Ok(byte - b'a' + 10),
        | b'A'..=b'F' => Ok(byte - b'A' + 10),
        | _ => bail!("expected hex"),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            Location,
            Locator,
        },
        std::path::PathBuf,
    };

    #[test]
    fn parses_file_device_and_yubikey_locations() {
        let locator = Locator::with_cwd(PathBuf::from("/tmp/agree"));
        assert_eq!(
            locator.parse("alice.share").unwrap(),
            Location::File(PathBuf::from("/tmp/agree/alice.share"))
        );
        assert_eq!(
            locator.parse("path=alice.share").unwrap(),
            Location::File(PathBuf::from("/tmp/agree/alice.share"))
        );
        assert!(locator.parse_share("alice.share").is_err());
        assert_eq!(
            locator.parse_share("path=alice.share").unwrap(),
            Location::File(PathBuf::from("/tmp/agree/alice.share"))
        );
        assert_eq!(
            locator.parse("device=/dev/rdisk4").unwrap(),
            Location::Device(PathBuf::from("/dev/rdisk4"))
        );
        assert_eq!(locator.parse("yubi=5fff20").unwrap(), Location::YubiKey {
            serial: None,
            object: 0x005f_ff20,
        });
        assert_eq!(locator.parse("yubi=42/5fff21").unwrap(), Location::YubiKey {
            serial: Some(42),
            object: 0x005f_ff21,
        });
        assert!(locator.parse("yubi=5fc105").is_ok());
        assert!(locator.parse("yubi=5FFF20").is_ok());
        assert!(locator.parse("yubi=00ff").is_err());
        assert!(locator.parse("yubi=").is_err());
        assert!(locator.parse("yubi=/5fff20").is_err());
        assert!(locator.parse("yubi=abc/5fff20").is_err());
        assert!(locator.parse("yubi=4294967296/5fff20").is_err());
        assert!(locator.parse("device=").is_err());
        assert!(locator.parse("path=").is_err());
        assert!(locator.parse("yubikey:5fff20").is_err());
        assert!(locator.parse("device:/dev/rdisk4").is_err());
        assert!(locator.parse("").is_err());
        assert!(locator.parse("yubi=5fffff1").is_err());
    }

    #[test]
    fn expands_tilde_and_resolves_relative_device_paths() {
        let locator = Locator {
            cwd: PathBuf::from("/work"),
            home: Some(PathBuf::from("/home/alice")),
        };
        assert_eq!(
            locator.parse("~/keys/secret.pem").unwrap(),
            Location::File(PathBuf::from("/home/alice/keys/secret.pem"))
        );
        assert_eq!(
            locator.parse("~").unwrap(),
            Location::File(PathBuf::from("/home/alice"))
        );
        assert_eq!(
            locator.parse("device=node.bin").unwrap(),
            Location::Device(PathBuf::from("/work/node.bin"))
        );
        let no_home = Locator {
            cwd: PathBuf::from("/work"),
            home: None,
        };
        assert!(no_home.parse("~/secret").unwrap_err().to_string().contains("HOME"));
    }

    #[cfg(feature = "yubikey")]
    #[test]
    fn reserved_objects_require_force_and_hex_is_strict() {
        use super::{
            decode_hex,
            ensure_object_allowed,
        };
        assert!(ensure_object_allowed(0x005f_c105, false).is_err());
        assert!(ensure_object_allowed(0x005f_c105, true).is_ok());
        assert!(ensure_object_allowed(0x005f_ff20, false).is_ok());
        assert!(decode_hex("aa").unwrap() == vec![0xaa]);
        assert!(decode_hex("AA").unwrap() == vec![0xaa]);
        assert!(decode_hex("a").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn unspecified_serial_uses_the_only_attached_key() {
        assert!(super::resolve_unspecified_serial(&[]).is_err());
        assert_eq!(super::resolve_unspecified_serial(&[42]).unwrap(), 42);
        assert!(super::resolve_unspecified_serial(&[1, 2])
            .unwrap_err()
            .to_string()
            .contains("multiple"));
    }
}
