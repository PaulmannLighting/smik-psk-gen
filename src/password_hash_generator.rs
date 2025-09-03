use base64::Engine;
use log::error;
use password_hash::rand_core::CryptoRng;
use password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use rand_core::SeedableRng;

use crate::psk::Psk;
use crate::{Error, BASE64};

/// A password hash generator.
pub struct PasswordHashGenerator<const SIZE: usize, R, H> {
    csprng: R,
    hasher: H,
}

impl<const SIZE: usize, R, H> PasswordHashGenerator<SIZE, R, H>
where
    R: CryptoRng,
    H: PasswordHasher,
{
    /// Create a new [`PasswordHashGenerator`] with a CSPRNG and a password hasher.
    #[must_use]
    pub const fn new(csprng: R, hasher: H) -> Self {
        Self { csprng, hasher }
    }

    /// Generates a random key of the specified size.
    pub fn generate(&mut self) -> [u8; SIZE] {
        let mut key = [0; SIZE];
        self.csprng.fill_bytes(&mut key);
        key
    }

    /// Verify a password hash.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the password hash could not be verified.
    pub fn verify(&self, psk: &Psk) -> Result<(), Error> {
        Ok(self
            .hasher
            .verify_password(&BASE64.decode(psk.base64())?, &psk.hash().try_into()?)?)
    }

    /// Hash the pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns a [`password_hash::Error`] if the hashing fails.
    pub fn hash(&mut self, key: &[u8]) -> password_hash::Result<String> {
        let salt = SaltString::from_rng(&mut self.csprng);
        self.hasher
            .hash_password(key, &salt)
            .map(|hash| hash.to_string())
    }
}

impl<const SIZE: usize, R, H> Default for PasswordHashGenerator<SIZE, R, H>
where
    R: CryptoRng + SeedableRng,
    H: PasswordHasher + Default,
{
    fn default() -> Self {
        Self::new(R::from_os_rng(), H::default())
    }
}

impl<const SIZE: usize, R, H> Iterator for PasswordHashGenerator<SIZE, R, H>
where
    R: CryptoRng,
    H: PasswordHasher,
{
    type Item = Psk;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.generate();
        let base64 = BASE64.encode(key);
        let hash = self
            .hash(&key)
            .inspect_err(|error| error!("Error hashing key: {error}"))
            .ok()?;
        let psk = Psk::new(base64, hash);
        self.verify(&psk)
            .inspect_err(|error| error!("Error validating PSK: {error}"))
            .ok()?;
        Some(psk)
    }
}
