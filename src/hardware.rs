//! Direct YubiKey PIV object reads and writes.
//!
//! A share, or a sealed secret that fits, is stored as the object bytes.
//! There is no second envelope. Objects below `5fff20` hold certificates and
//! admin data, so they are refused unless `--force` is set.
//!
//! The `yubikey` feature is on by default. Static musl builds that cannot link
//! PC/SC turn it off and reject `yubi=` locations with a clear error.

#[cfg(not(feature = "yubikey"))]
use crate::error::Error;
#[cfg(feature = "yubikey")]
use crate::location::{
    decode_hex,
    ensure_object_allowed,
    YUBIKEY_OBJECT_MAX,
};
#[cfg(not(feature = "yubikey"))]
use anyhow::Context;
use anyhow::Result;

#[cfg(feature = "yubikey")]
#[path = "piv_aes.rs"]
mod piv_aes;

#[cfg(feature = "yubikey")]
mod session {
    use {
        super::{
            ensure_object_allowed,
            YUBIKEY_OBJECT_MAX,
        },
        crate::error::Error,
        anyhow::{
            Context,
            Result,
        },
        yubikey::{
            MgmKey,
            Serial,
            YubiKey,
        },
        zeroize::Zeroize,
    };

    pub(crate) struct YubiKeyStore {
        serial: Option<u32>,
        pin: Vec<u8>,
        management_key: MgmKey,
    }

    impl YubiKeyStore {
        pub(crate) fn open(serial: Option<u32>, pin: Vec<u8>, management_key: Option<&str>) -> Result<Self> {
            if pin.is_empty() || pin.len() > 8 {
                return Err(Error::InvalidPin.into());
            }
            Ok(Self {
                serial,
                pin,
                management_key: management_key_from_flag(management_key)?,
            })
        }

        pub(crate) fn exists(&self, object: u32) -> Result<bool> {
            if self.aes192()? {
                return super::piv_aes::object_exists(self.serial(), &self.pin, self.management_key.as_ref(), object);
            }
            let mut key = self.connect()?;
            match key.fetch_object(object) {
                | Ok(_) => Ok(true),
                | Err(yubikey::Error::NotFound) => Ok(false),
                | Err(err) => Err(err).with_context(|| format!("Failed to read YubiKey object {object:06x}")),
            }
        }

        pub(crate) fn write(&self, object: u32, bytes: &[u8], force: bool) -> Result<()> {
            ensure_object_allowed(object, force)?;
            if bytes.len() > YUBIKEY_OBJECT_MAX {
                return Err(Error::YubiKeyTooLarge {
                    len: bytes.len(),
                    max: YUBIKEY_OBJECT_MAX,
                }
                .into());
            }
            if self.aes192()? {
                return super::piv_aes::write_object(
                    self.serial(),
                    &self.pin,
                    self.management_key.as_ref(),
                    object,
                    bytes,
                    force,
                );
            }
            let mut key = self.connect()?;
            match key.fetch_object(object) {
                | Ok(_) if !force => {
                    anyhow::bail!("YubiKey object {object:06x} already exists. Use --force to overwrite it.");
                },
                | Ok(_) | Err(yubikey::Error::NotFound) => {},
                | Err(_) if force => {},
                | Err(err) => {
                    return Err(err)
                        .with_context(|| format!("Failed to read YubiKey object {object:06x} before write"));
                },
            }
            let mut payload = bytes.to_vec();
            key.save_object(object, &mut payload)
                .with_context(|| format!("Failed to write YubiKey object {object:06x}"))?;
            Ok(())
        }

        fn serial(&self) -> Option<u32> {
            self.serial
        }

        fn aes192(&self) -> Result<bool> {
            let Some(serial) = self.serial else {
                return Ok(false);
            };
            Ok(matches!(
                super::piv_aes::management_algorithm(serial)?,
                super::piv_aes::ManagementAlgorithm::Aes192
            ))
        }

        fn connect(&self) -> Result<YubiKey> {
            let mut key = match self.serial {
                | Some(serial) => {
                    YubiKey::open_by_serial(Serial(serial))
                        .with_context(|| format!("Failed to open YubiKey {serial}"))?
                },
                | None => YubiKey::open().context("Failed to open YubiKey")?,
            };
            key.verify_pin(&self.pin).map_err(super::pin_failure)?;
            key.authenticate(self.management_key.clone())
                .context("YubiKey management key authentication failed")?;
            Ok(key)
        }
    }

    impl Drop for YubiKeyStore {
        fn drop(&mut self) {
            self.pin.zeroize();
        }
    }

    impl std::fmt::Debug for YubiKeyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("YubiKeyStore")
                .field("serial", &self.serial)
                .field("pin", &"<redacted>")
                .finish_non_exhaustive()
        }
    }

    fn management_key_from_flag(value: Option<&str>) -> Result<MgmKey> {
        let Some(value) = value else {
            return Ok(MgmKey::default());
        };
        let bytes = super::decode_hex(value).context("management key must be hex")?;
        MgmKey::from_bytes(&bytes).context("management key must be 24 bytes and must not be a weak DES key")
    }

    pub(crate) fn validate_management_key(value: &str) -> Result<()> {
        management_key_from_flag(Some(value)).map(|_| ())
    }
}

#[cfg(not(feature = "yubikey"))]
mod session {
    use {
        super::Error,
        anyhow::Result,
    };

    #[derive(Debug)]
    pub(crate) struct YubiKeyStore;

    impl YubiKeyStore {
        pub(crate) fn open(_serial: Option<u32>, pin: Vec<u8>, _management_key: Option<&str>) -> Result<Self> {
            if pin.is_empty() || pin.len() > 8 {
                return Err(Error::InvalidPin.into());
            }
            anyhow::bail!("this binary was built without YubiKey support; rebuild with --features yubikey");
        }

        pub(crate) fn exists(&self, _object: u32) -> Result<bool> {
            anyhow::bail!("this binary was built without YubiKey support; rebuild with --features yubikey");
        }

        pub(crate) fn write(&self, _object: u32, _bytes: &[u8], _force: bool) -> Result<()> {
            anyhow::bail!("this binary was built without YubiKey support; rebuild with --features yubikey");
        }
    }
}

pub(crate) use session::YubiKeyStore;

/// The PIV applet reports a blocked PIN as a wrong PIN with zero tries left.
/// Say that explicitly so a FIDO2 PIN is not retried until the applet locks.
#[cfg(feature = "yubikey")]
fn pin_failure(err: yubikey::Error) -> anyhow::Error {
    match err {
        | yubikey::Error::WrongPin { tries: 0 } | yubikey::Error::PinLocked => {
            anyhow::anyhow!(
                "PIV PIN is blocked (0 tries remaining). agree uses the PIV PIN, not the FIDO2 PIN. Unblock it with \
                 the PUK, or reset the PIV application. Do not keep retrying."
            )
        },
        | yubikey::Error::WrongPin { tries } => {
            anyhow::anyhow!(
                "PIV PIN was rejected ({tries} tries remaining). agree uses the PIV PIN, not the FIDO2 PIN used for \
                 passkeys."
            )
        },
        | other => anyhow::Error::from(other).context("YubiKey PIN verification failed"),
    }
}

/// Read one share object. PIN verification only; the management key is a write
/// credential.
#[cfg(feature = "yubikey")]
pub(crate) fn read_object(serial: u32, pin: &[u8], object: u32) -> Result<Vec<u8>> {
    use anyhow::Context;
    if pin.is_empty() || pin.len() > 8 {
        return Err(crate::error::Error::InvalidPin.into());
    }
    let mut key = yubikey::YubiKey::open_by_serial(yubikey::Serial(serial))
        .with_context(|| format!("Failed to open YubiKey {serial}"))?;
    key.verify_pin(pin).map_err(pin_failure)?;
    let buffer = key
        .fetch_object(object)
        .with_context(|| format!("Failed to read YubiKey {serial} object {object:06x}"))?;
    Ok(buffer.to_vec())
}

/// A YubiKey this build opened without a PIN. Listing does not write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct AttachedYubiKey {
    pub(crate) serial: u32,
    pub(crate) version: String,
    pub(crate) reader: String,
}

/// YubiKeys currently available to `yubi=` locations. Empty if none are
/// present. A reader that does not open is skipped; a PC/SC failure is an
/// error.
#[cfg(feature = "yubikey")]
pub(crate) fn list_attached() -> Result<Vec<AttachedYubiKey>> {
    use anyhow::Context;
    let mut context = yubikey::Context::open().context("Failed to list YubiKeys")?;
    let mut found = Vec::new();
    for reader in context.iter().context("Failed to list YubiKey readers")? {
        if let Ok(key) = reader.open() {
            found.push(AttachedYubiKey {
                serial: u32::from(key.serial()),
                version: key.version().to_string(),
                reader: key.name().to_string(),
            });
        }
    }
    found.sort_by_key(|key| key.serial);
    found.dedup_by_key(|key| key.serial);
    Ok(found)
}

/// Serial numbers of attached YubiKeys. Empty if none are present.
#[cfg(feature = "yubikey")]
pub(crate) fn list_serials() -> Result<Vec<u32>> {
    Ok(list_attached()?.into_iter().map(|key| key.serial).collect())
}

#[cfg(not(feature = "yubikey"))]
pub(crate) fn read_object(_serial: u32, _pin: &[u8], _object: u32) -> Result<Vec<u8>> {
    anyhow::bail!("this binary was built without YubiKey support; rebuild with --features yubikey");
}

#[cfg(not(feature = "yubikey"))]
pub(crate) fn list_attached() -> Result<Vec<AttachedYubiKey>> {
    anyhow::bail!("this binary was built without YubiKey support; rebuild with --features yubikey");
}

#[cfg(not(feature = "yubikey"))]
pub(crate) fn list_serials() -> Result<Vec<u32>> {
    Ok(list_attached()?.into_iter().map(|key| key.serial).collect())
}

/// Reject a malformed management key before a card is opened.
pub(crate) fn validate_management_key(value: &str) -> Result<()> {
    #[cfg(feature = "yubikey")]
    {
        session::validate_management_key(value)
    }
    #[cfg(not(feature = "yubikey"))]
    {
        let bytes = crate::location::decode_hex(value).context("management key must be hex")?;
        if bytes.len() != 24 {
            anyhow::bail!("management key must be 24 bytes and must not be a weak DES key");
        }
        Ok(())
    }
}

/// Whether that serial currently answers PC/SC. Absence is `false`, not an
/// error.
#[cfg(feature = "yubikey")]
pub(crate) fn serial_present(serial: u32) -> bool {
    yubikey::YubiKey::open_by_serial(yubikey::Serial(serial)).is_ok()
}

#[cfg(not(feature = "yubikey"))]
pub(crate) fn serial_present(_serial: u32) -> bool {
    false
}

#[cfg(test)]
mod validate_tests {
    #[test]
    fn rejects_a_bad_management_key_without_opening_a_device() {
        let err = super::validate_management_key("zz").unwrap_err().to_string();
        assert!(err.contains("hex"), "{err}");
    }
}

#[cfg(all(test, feature = "yubikey"))]
mod tests {
    use super::YubiKeyStore;

    #[test]
    fn rejects_bad_pin_key_and_object_without_opening_a_device() {
        let err = YubiKeyStore::open(None, Vec::new(), None).unwrap_err().to_string();
        assert!(err.contains("PIN"), "{err}");
        let err = YubiKeyStore::open(None, b"123456789".to_vec(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("PIN"), "{err}");
        let err = YubiKeyStore::open(None, b"123456".to_vec(), Some("zz"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("hex") || err.contains("management"), "{err}");
        let err = YubiKeyStore::open(None, b"123456".to_vec(), Some("0011"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("24 bytes") || err.contains("management"), "{err}");

        let store = YubiKeyStore::open(None, b"123456".to_vec(), None).unwrap();
        let err = store.write(0x005f_c105, b"share", false).unwrap_err().to_string();
        assert!(err.contains("reserved") || err.contains("5fc105"), "{err}");
        let err = store
            .write(0x005f_ff20, &vec![0u8; 3064], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("3063"), "{err}");
    }
}

#[cfg(all(test, not(feature = "yubikey")))]
mod tests {
    use super::YubiKeyStore;

    #[test]
    fn built_without_the_feature_rejects_before_any_device_call() {
        let err = YubiKeyStore::open(None, b"123456".to_vec(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("without YubiKey support"), "{err}");
    }
}
