mod error;

use crate::BASE64;
use base64::Engine;
pub use error::Error;
use password_hash::PasswordVerifier;

pub trait PasswordVerifierExt: PasswordVerifier {
    /// Verifies a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if verification fails.
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
