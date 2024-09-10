mod error;

use crate::BASE64;
use base64::Engine;
pub use error::Error;
use password_hash::PasswordVerifier;

/// Extends [`PasswordVerifier`] with a method to verify a password from a base64-encoded key.
pub trait PasswordVerifierExt: PasswordVerifier {
    /// Verifies a password.
    ///
    /// # Errors
    /// Returns an [`password_hash::Error`] if verification fails.
    fn verify_base64(&self, b64key: &str, hash: &str) -> Result<(), Error>;
}

impl<T> PasswordVerifierExt for T
where
    T: PasswordVerifier,
{
    fn verify_base64(&self, b64key: &str, hash: &str) -> Result<(), Error> {
        Ok(self.verify_password(&BASE64.decode(b64key)?, &hash.try_into()?)?)
    }
}
