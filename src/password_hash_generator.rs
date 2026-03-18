use std::marker::PhantomData;

use base64::Engine;
use password_hash::rand_core::TryRng;
use password_hash::{PasswordHasher, PasswordVerifier};
use rand::{CryptoRng, SeedableRng};

use crate::constants::BASE64;
use crate::error::Error;
use crate::psk::Psk;

/// A password hash generator.
pub struct PasswordHashGenerator<const SIZE: usize, R, H, P> {
    csprng: R,
    hasher: H,
    _phantom: PhantomData<P>,
}

impl<const SIZE: usize, R, H, P> PasswordHashGenerator<SIZE, R, H, P> {
    /// Create a new [`PasswordHashGenerator`] with a CSPRNG and a password hasher.
    #[must_use]
    pub const fn new(csprng: R, hasher: H) -> Self {
        Self {
            csprng,
            hasher,
            _phantom: PhantomData,
        }
    }

    /// Attempt to create a `PasswordHashGenerator` from a random number generator.
    ///
    /// # Errors
    ///
    /// Returns `<T as TryRng>::Error` if instantiating the RNG fails.
    pub fn try_from_rng<T>(rng: &mut T) -> Result<Self, T::Error>
    where
        T: TryRng,
        R: SeedableRng,
        H: Default,
    {
        R::try_from_rng(rng).map(|csprng| Self::new(csprng, H::default()))
    }

    /// Generates a random key of the specified size.
    #[must_use]
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
    pub fn verify(&self, psk: &Psk<P>) -> Result<(), Error>
    where
        H: PasswordVerifier<P>,
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
    pub fn hash(&mut self, key: &[u8]) -> password_hash::Result<P>
    where
        R: CryptoRng,
        H: PasswordHasher<P>,
    {
        self.hasher.hash_password_with_rng(&mut self.csprng, key)
    }
}

/// Iterator to generate an infinite stream of PSKs.
///
/// # Errors
///
/// Since PSK generation may fail, this will actually yield a `Result<Psk, Error>`,
/// which should be handled by the caller.
impl<const SIZE: usize, R, H, P> Iterator for PasswordHashGenerator<SIZE, R, H, P>
where
    R: CryptoRng,
    H: PasswordHasher<P> + PasswordVerifier<P>,
{
    type Item = Result<Psk<P>, Error>;

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
