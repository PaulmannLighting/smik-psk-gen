use std::fmt::Display;

/// An error that can occur when generating a password hash.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// An error that can occur when hashing a password.
    PasswordHash(password_hash::Error),
    /// An error that can occur when decoding a BASE64 string.
    Base64(base64::DecodeError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordHash(error) => write!(f, "Argon2 error: {error}"),
            Self::Base64(error) => write!(f, "Base64 error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PasswordHash(error) => Some(error),
            Self::Base64(error) => Some(error),
        }
    }
}

impl From<password_hash::Error> for Error {
    fn from(error: password_hash::Error) -> Self {
        Self::PasswordHash(error)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        Self::Base64(error)
    }
}
