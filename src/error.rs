/// Stable failures callers match, display, or test.
///
/// Contextual IO and validation failures use `anyhow` at the call site.
/// Variants here are the ones with a fixed recovery action or a security
/// meaning.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("{command} is experimental; re-run with --experimental")]
    Experimental { command: &'static str },

    #[error("blueprint contains a shell password provider; re-run with --trust to allow it")]
    ShellNotTrusted,

    #[error("share is encrypted; re-run with --interactive to enter the password")]
    PasswordRequired,

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("share password must not be empty")]
    EmptyPassword,

    #[error("share password exceeds {max} bytes")]
    PasswordTooLong { max: usize },

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("failed to encrypt share")]
    EncryptionFailed,

    #[error("secret authentication failed")]
    AuthenticationFailed,

    #[error("duplicate share: {path}")]
    DuplicateShare { path: String },

    #[error("invalid archive identifier")]
    InvalidIdentifier,

    #[error("invalid archive version")]
    InvalidVersion,

    #[error("invalid share archive: {0}")]
    InvalidArchive(String),
}
