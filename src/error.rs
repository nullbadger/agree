/// Failures a caller can match or print without seeing secret material.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("need at least {need} shares to restore this secret; received {got}")]
    NeedShares { need: u8, got: usize },

    #[error("secret authentication failed")]
    AuthenticationFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("failed to encrypt")]
    EncryptionFailed,

    #[error("format revision {found} is not this agree; this binary only reads revision {expected}")]
    UnsupportedRevision { found: u8, expected: u8 },

    #[error("share does not belong to this sealed secret")]
    WrongGroup,

    #[error("duplicate share")]
    DuplicateShare,

    #[error("share is password protected")]
    PasswordRequired,

    #[error("share password must not be empty")]
    EmptyPassword,

    #[error("share password exceeds {max} bytes")]
    PasswordTooLong { max: usize },

    #[error("YubiKey PIN must be 1 to 8 bytes")]
    InvalidPin,

    #[error(
        "YubiKey PIV objects hold at most {max} bytes; this payload is {len} bytes. Put shares on the YubiKey and the \
         sealed secret on a file or device:"
    )]
    YubiKeyTooLarge { len: usize, max: usize },

    #[cfg(feature = "yubikey")]
    #[error("refusing to overwrite a reserved YubiKey object {object:06x} without --force")]
    ReservedObject { object: u32 },

    #[error("writing to a device requires --force")]
    DeviceNeedsForce,

    #[error("refusing to write secret bytes to a terminal")]
    TerminalOutput,

    #[error("mlock failed ({reason}); refusing to continue")]
    MlockFailed { reason: String },
}
