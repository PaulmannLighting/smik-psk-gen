use base64::Engine;

use crate::constants::BASE64;

/// Pre-shared Key (PSK) consisting of the plain text password and its password hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk<T> {
    key: Box<[u8]>,
    hash: T,
}

impl<T> Psk<T> {
    /// Create a new `Psk` instance.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the provided key and hash match.
    #[expect(unsafe_code)]
    #[must_use]
    pub const unsafe fn new(key: Box<[u8]>, hash: T) -> Self {
        Self { key, hash }
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
