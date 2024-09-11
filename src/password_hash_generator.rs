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
    buffer: Vec<u8>,
}

impl<R, H> PasswordHashGenerator<R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    #[must_use]
    pub fn new(csprng: R, hasher: H, size: usize) -> Self {
        Self {
            csprng,
            hasher,
            buffer: vec![0; size],
        }
    }

    /// Generates a random password and writes it into the buffer returning its BASE64 encoding.
    ///
    /// # Errors
    /// Returns a [`password_hash::Error`] if the password hash could not be generated.
    pub fn generate(&mut self) -> password_hash::Result<(String, String)> {
        self.csprng.fill_bytes(&mut self.buffer);
        let b64 = BASE64.encode(&self.buffer);
        let salt = SaltString::generate(&mut self.csprng);
        let hash = self.hasher.hash_password(&self.buffer, &salt)?;
        self.buffer.iter_mut().for_each(|byte| *byte = 0);
        Ok((b64, hash.to_string()))
    }

    /// Verify a password hash.
    ///
    /// # Errors
    /// Returns an [`Error`] if the password hash could not be verified.
    pub fn verify(&self, b64key: &str, hash: &str) -> Result<(), Error> {
        Ok(self
            .hasher
            .verify_password(&BASE64.decode(b64key)?, &hash.try_into()?)?)
    }
}

impl<R, H> PasswordHashGenerator<R, H>
where
    R: CryptoRngCore + SeedableRng,
    H: PasswordHasher + Default,
{
    #[must_use]
    pub fn default_with_size(size: usize) -> Self {
        Self::new(R::from_entropy(), H::default(), size)
    }
}
