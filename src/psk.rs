#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Psk {
    plaintext: String,
    hash: String,
}

impl Psk {
    /// Creates a new `Psk` instance.
    pub const fn new(plaintext: String, hash: String) -> Self {
        Self { plaintext, hash }
    }

    /// Returns the plaintext password.
    pub fn plaintext(&self) -> &str {
        self.plaintext.as_str()
    }

    /// Returns the hashed password.
    pub fn hash(&self) -> &str {
        self.hash.as_str()
    }
}
