use argon2::{
    password_hash::Result, password_hash::SaltString, Argon2,
    PasswordHasher as Argon2PasswordHasher, PasswordVerifier,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

pub struct PasswordHasher<'key, R>
where
    R: CryptoRngCore,
{
    csprng: R,
    argon2: Argon2<'key>,
}

impl<R> PasswordHasher<'_, R>
where
    R: CryptoRngCore,
{
    /// Hash a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if hashing fails.
    pub fn hash(&mut self, password: &[u8]) -> Result<String> {
        let salt = SaltString::generate(&mut self.csprng);
        let hash = self.argon2.hash_password(password, &salt)?;
        Ok(hash.to_string())
    }

    /// Verifies a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if verification fails.
    pub fn verify_password(&mut self, password: &[u8], hash: &str) -> Result<()> {
        self.argon2.verify_password(password, &hash.try_into()?)
    }
}

impl Default for PasswordHasher<'_, ChaCha20Rng> {
    fn default() -> Self {
        Self {
            csprng: ChaCha20Rng::from_entropy(),
            argon2: Argon2::default(),
        }
    }
}
