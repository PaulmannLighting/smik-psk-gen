/// Pre-shared Key (PSK) consisting of the base64-encoded plain text and the hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk<T> {
    base64: String,
    hash: T,
}

impl<T> Psk<T> {
    /// Creates a new `Psk` instance.
    pub(crate) const fn new(base64: String, hash: T) -> Self {
        Self { base64, hash }
    }

    /// Returns the plaintext password.
    pub const fn base64(&self) -> &str {
        self.base64.as_str()
    }

    /// Returns the hashed password.
    pub const fn hash(&self) -> &T {
        &self.hash
    }
}
