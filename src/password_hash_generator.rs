use argon2::PasswordHash;
use base64::Engine;
use password_hash::{PasswordHasher, PasswordVerifier};
use rand::rngs::SysRng;
use rand::{CryptoRng, SeedableRng};

use crate::constants::BASE64;
use crate::error::Error;
use crate::psk::Psk;

/// A password hash generator.
pub struct PasswordHashGenerator<const SIZE: usize, R, H> {
    csprng: R,
    hasher: H,
}

impl<const SIZE: usize, R, H> PasswordHashGenerator<SIZE, R, H> {
    /// Create a new [`PasswordHashGenerator`] with a CSPRNG and a password hasher.
    #[must_use]
    pub const fn new(csprng: R, hasher: H) -> Self {
        Self { csprng, hasher }
    }

    /// Generates a random key of the specified size.
    pub fn generate(&mut self) -> [u8; SIZE]
    where
        R: CryptoRng,
    {
        let mut key = [0; SIZE];
        self.csprng.fill_bytes(&mut key);
        key
    }

    /// Verify a password hash.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the password hash could not be verified.
    pub fn verify(&self, psk: &Psk) -> Result<(), Error>
    where
        H: PasswordVerifier<PasswordHash>,
    {
        Ok(self
            .hasher
            .verify_password(&BASE64.decode(psk.base64())?, psk.hash())?)
    }

    /// Hash the pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns a [`password_hash::Error`] if the hashing fails.
    pub fn hash(&mut self, key: &[u8]) -> password_hash::Result<PasswordHash>
    where
        R: CryptoRng,
        H: PasswordHasher<PasswordHash>,
    {
        self.hasher.hash_password_with_rng(&mut self.csprng, key)
    }
}

impl<const SIZE: usize, R, H> Default for PasswordHashGenerator<SIZE, R, H>
where
    R: SeedableRng,
    H: Default,
{
    fn default() -> Self {
        Self::new(
            R::try_from_rng(&mut SysRng).expect("Creating RNG from OS RNG should always succeed."),
            H::default(),
        )
    }
}

/// Iterator to generate an infinite stream of PSKs.
///
/// # Errors
///
/// Since PSK generation may fail, this will actually yield a `Result<Psk, Error>`,
/// which should be handled by the caller.
impl<const SIZE: usize, R, H> Iterator for PasswordHashGenerator<SIZE, R, H>
where
    R: CryptoRng,
    H: PasswordHasher<PasswordHash> + PasswordVerifier<PasswordHash>,
{
    type Item = Result<Psk, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.generate();
        let hash = match self.hash(&key) {
            Ok(hash) => hash,
            Err(error) => return Some(Err(error.into())),
        };

        let psk = Psk::new(BASE64.encode(key), hash);

        if let Err(error) = self.verify(&psk) {
            return Some(Err(error));
        }

        Some(Ok(psk))
    }
}
