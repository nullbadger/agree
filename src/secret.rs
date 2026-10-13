use {
    crate::error::Error,
    std::fmt,
    zeroize::{
        Zeroize,
        ZeroizeOnDrop,
    },
};

/// Maximum accepted share password, including shell-provider output after
/// newline trimming.
pub(crate) const MAX_PASSWORD_BYTES: usize = 4096;

/// A share password. The buffer is cleared when the value is dropped, including
/// on error paths.
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

    pub(crate) fn as_str(&self) -> &str {
        &self.0
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

/// Owned secret material. Drop clears the buffer, so callers do not zeroize by
/// hand.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        Self(self.0.split_off(at))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
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
        assert_eq!(
            Password::new("correct horse".to_owned()).unwrap().as_str(),
            "correct horse"
        );
    }
}
