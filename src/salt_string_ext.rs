use password_hash::{PasswordHasher, SaltString};

/// Extends [`SaltString`] with a method to hash a password.
pub trait SaltStringExt {
    /// Use this salt to hash a password.
    ///
    /// # Errors
    /// Returns an [`password_hash::Error`] if hashing fails.
    fn hash<H>(&self, password: &[u8], hasher: &H) -> password_hash::Result<String>
    where
        H: PasswordHasher;
}

impl SaltStringExt for SaltString {
    fn hash<H>(&self, password: &[u8], hasher: &H) -> password_hash::Result<String>
    where
        H: PasswordHasher,
    {
        hasher
            .hash_password(password, self)
            .map(|hash| hash.to_string())
    }
}
