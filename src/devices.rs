//! Attached hardware `agree devices` can name.
//!
//! Each kind lists itself and appends its own variant. A kind this build
//! cannot open is absent, not an error. A kind that is compiled in and fails
//! to talk to its stack is an error. `device:` paths are not listed; those are
//! nodes the operator already has.
//!
//! Adding a kind is a variant on [`AttachedDevice`] and a source function
//! called from [`list`]. The command prints whatever that returns.

use {crate::hardware::AttachedYubiKey, anyhow::Result, std::fmt};

/// One piece of hardware this build opened without a PIN.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum AttachedDevice {
    YubiKey(AttachedYubiKey),
}

impl fmt::Display for AttachedDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::YubiKey(key) => {
                write!(
                    f,
                    "yubikey:{}  version {}  reader {}",
                    key.serial, key.version, key.reader
                )
            },
        }
    }
}

/// Hardware currently available to a share or sealed destination.
pub(crate) fn list() -> Result<Vec<AttachedDevice>> {
    let mut found = Vec::new();
    yubikeys(&mut found)?;
    Ok(found)
}

#[cfg(feature = "yubikey")]
fn yubikeys(found: &mut Vec<AttachedDevice>) -> Result<()> {
    found.extend(
        crate::hardware::list_attached()?
            .into_iter()
            .map(AttachedDevice::YubiKey),
    );
    Ok(())
}

#[cfg(not(feature = "yubikey"))]
fn yubikeys(_found: &mut Vec<AttachedDevice>) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::AttachedDevice, crate::hardware::AttachedYubiKey};

    #[test]
    fn yubikey_line_uses_the_location_prefix() {
        let device = AttachedDevice::YubiKey(AttachedYubiKey {
            serial: 7,
            version: "5.7.1".to_owned(),
            reader: "Yubico YubiKey".to_owned(),
        });
        assert_eq!(device.to_string(), "yubikey:7  version 5.7.1  reader Yubico YubiKey");
    }
}
