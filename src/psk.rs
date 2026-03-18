use argon2::PasswordHash;

/// Pre-shared Key (PSK) consisting of the base64-encoded plain text and the hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk {
    base64: String,
    hash: PasswordHash,
}

impl Psk {
    /// Creates a new `Psk` instance.
    pub(crate) const fn new(base64: String, hash: PasswordHash) -> Self {
        Self { base64, hash }
    }

    /// Returns the plaintext password.
    pub const fn base64(&self) -> &str {
        self.base64.as_str()
    }

    /// Returns the hashed password.
    pub const fn hash(&self) -> &PasswordHash {
        &self.hash
    }
}
