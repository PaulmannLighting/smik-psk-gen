mod pw_hasher;

use argon2::PasswordHasher;
use pw_hasher::PwHasher;
use rand_core::CryptoRngCore;

pub trait Hasher: CryptoRngCore + Sized {
    /// Hash a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if hashing fails.
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
