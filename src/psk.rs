use base64::Engine;

use crate::constants::BASE64;

/// Pre-shared Key (PSK) consisting of the plain text password and a password hash.
///
/// # Invariants
///
/// This structure does *not* guarantee, that the provided key and hash match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk<T> {
    key: Box<[u8]>,
    hash: T,
}

impl<T> Psk<T> {
    /// Creates a new `Psk` instance.
    #[must_use]
    pub const fn new(key: Box<[u8]>, hash: T) -> Self {
        Self { key, hash }
    }

    /// Return the plain text key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Return the password hash.
    #[must_use]
    pub const fn hash(&self) -> &T {
        &self.hash
    }

    /// Return the base64 encoding of the plain text password.
    #[must_use]
    pub fn base64(&self) -> String {
        BASE64.encode(&self.key)
    }
}
