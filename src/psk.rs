/// Pre-shared Key (PSK) consisting of the base64-encoded plain text and the hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk {
    base64: String,
    hash: String,
}

impl Psk {
    /// Creates a new `Psk` instance.
    pub(crate) const fn new(base64: String, hash: String) -> Self {
        Self { base64, hash }
    }

    /// Returns the plaintext password.
    pub fn base64(&self) -> &str {
        self.base64.as_str()
    }

    /// Returns the hashed password.
    pub fn hash(&self) -> &str {
        self.hash.as_str()
    }
}
