#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("experimental: {0}")]
    Experimental(String),
    #[error("argument: {0}")]
    Argument(String),
    #[error("unknown command")]
    UnknownCommand,
    #[error("no trust")]
    NoTrust,
    #[error("non interactive")]
    NonInteractive,
    #[error("decoding error: {0}")]
    Decoding(String),
    #[error("mismatched shares")]
    MismatchedShares,
    #[error("secret authentication failed")]
    AuthenticationFailed,
    #[error("password mismatch")]
    PasswordMismatch,
    #[error("duplicate share: {0}")]
    DuplicateShare(String),
    #[error("decryption failed")]
    Decryption,
}
