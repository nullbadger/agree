use {
    crate::error::Error,
    std::fmt,
    zeroize::{
        Zeroize,
        ZeroizeOnDrop,
    },
};

/// Maximum accepted share password, including a stdin line after newline
/// trimming.
pub(crate) const MAX_PASSWORD_BYTES: usize = 4096;

/// A share password. The buffer is cleared when the value is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Password(String);

impl Password {
    pub(crate) fn new(mut value: String) -> Result<Self, Error> {
        if value.is_empty() {
            value.zeroize();
            return Err(Error::EmptyPassword);
        }
        if value.len() > MAX_PASSWORD_BYTES {
            value.zeroize();
            return Err(Error::PasswordTooLong {
                max: MAX_PASSWORD_BYTES,
            });
        }
        Ok(Self(value))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Password,
        MAX_PASSWORD_BYTES,
    };

    #[test]
    fn rejects_empty_and_overlong_passwords() {
        assert!(Password::new(String::new()).is_err());
        assert!(Password::new("x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert!(Password::new("correct horse".to_owned()).is_ok());
    }
}
