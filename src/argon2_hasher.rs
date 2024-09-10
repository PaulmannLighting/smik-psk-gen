use argon2::{
    password_hash::{Result, SaltString},
    Argon2, PasswordHasher,
};
use rand_core::CryptoRngCore;

pub trait Argon2Hasher: CryptoRngCore {
    /// Hash a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if hashing fails.
    fn hash_argon2(&mut self, argon2: &Argon2<'_>, password: &[u8]) -> Result<String>;
}

impl<T> Argon2Hasher for T
where
    T: CryptoRngCore,
{
    fn hash_argon2(&mut self, argon2: &Argon2<'_>, password: &[u8]) -> Result<String> {
        Ok(argon2
            .hash_password(password, &SaltString::generate(self))?
            .to_string())
    }
}
