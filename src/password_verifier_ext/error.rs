use std::fmt::Display;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Argon2(argon2::password_hash::Error),
    Base64(base64::DecodeError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2(error) => write!(f, "Argon2 error: {error}"),
            Self::Base64(error) => write!(f, "Base64 error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Argon2(error) => Some(error),
            Self::Base64(error) => Some(error),
        }
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from(error: argon2::password_hash::Error) -> Self {
        Self::Argon2(error)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        Self::Base64(error)
    }
}
