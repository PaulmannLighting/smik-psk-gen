use std::marker::PhantomData;

use password_hash::rand_core::TryRng;
use password_hash::{PasswordHasher, PasswordVerifier};
use rand::{CryptoRng, SeedableRng};

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

    /// Generate a random key of the specified size.
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
    /// Returns a [`password_hash::Error`] if the password hash could not be verified.
    pub fn verify(&self, key: &[u8], hash: &P) -> password_hash::Result<()>
    where
        H: PasswordVerifier<P>,
    {
        self.hasher.verify_password(key, hash)
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
/// Since password hash generation may fail, this will actually yield a
/// `password_hash::Result<Psk>`, which should be handled by the caller.
impl<const SIZE: usize, R, H, P> Iterator for PasswordHashGenerator<SIZE, R, H, P>
where
    R: CryptoRng,
    H: PasswordHasher<P> + PasswordVerifier<P>,
{
    type Item = password_hash::Result<Psk<P>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.generate();
        let hash = match self.hash(&key) {
            Ok(hash) => hash,
            Err(error) => return Some(Err(error)),
        };

        #[expect(unsafe_code)]
        // SAFETY: We calculated the correct hash for they above.
        Some(Ok(unsafe { Psk::new(key.into(), hash) }))
    }
}
