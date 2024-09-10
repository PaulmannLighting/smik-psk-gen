mod pw_hasher;

use password_hash::PasswordHasher;
use pw_hasher::PwHasher;
use rand_core::CryptoRngCore;

/// A trait for hashing passwords.
pub trait Hasher: CryptoRngCore + Sized {
    /// Create a password hasher.
    fn hasher<'a, P>(&'a mut self, password_hasher: &'a P) -> PwHasher<'a, Self, P>
    where
        P: PasswordHasher;
}

impl<T> Hasher for T
where
    T: CryptoRngCore + Sized,
{
    fn hasher<'a, P>(&'a mut self, password_hasher: &'a P) -> PwHasher<'a, Self, P>
    where
        P: PasswordHasher,
    {
        PwHasher::new(self, password_hasher)
    }
}
