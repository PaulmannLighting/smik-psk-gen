use crate::{Error, BASE64};
use base64::Engine;
use password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use rand_core::{CryptoRngCore, SeedableRng};

pub struct PasswordHashGenerator<R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    csprng: R,
    hasher: H,
}

impl<R, H> PasswordHashGenerator<R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    #[must_use]
    pub const fn new(csprng: R, hasher: H) -> Self {
        Self { csprng, hasher }
    }

    /// Generates a random password and writes it into the buffer returning its BASE64 encoding.
    pub fn generate(&mut self, buffer: &mut [u8]) -> String {
        self.csprng.fill_bytes(buffer);
        BASE64.encode(buffer)
    }

    /// Hashes a password.
    ///
    /// # Errors
    /// Returns a [`password_hash::Error`] if the password hash could not be generated.
    pub fn hash(&mut self, password: &[u8]) -> password_hash::Result<String> {
        let salt = SaltString::generate(&mut self.csprng);
        self.hasher
            .hash_password(password, &salt)
            .map(|hash| hash.to_string())
    }

    /// Verify a password hash.
    ///
    /// # Errors
    /// Returns an [`Error`] if the password hash could not be verified.
    pub fn verify_base64(&self, b64key: &str, hash: &str) -> Result<(), Error> {
        Ok(self
            .hasher
            .verify_password(&BASE64.decode(b64key)?, &hash.try_into()?)?)
    }
}

impl<R, H> Default for PasswordHashGenerator<R, H>
where
    R: CryptoRngCore + SeedableRng,
    H: PasswordHasher + Default,
{
    fn default() -> Self {
        Self::new(R::from_entropy(), H::default())
    }
}
