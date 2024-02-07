use argon2::{
    password_hash::Result, password_hash::SaltString, Argon2, PasswordHasher, PasswordVerifier,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

pub struct PwHasher<'key, R>
where
    R: CryptoRngCore,
{
    csprng: R,
    argon2: Argon2<'key>,
}

impl<R> PwHasher<'_, R>
where
    R: CryptoRngCore,
{
    /// Hash a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if hashing fails.
    pub fn hash(&mut self, password: &[u8]) -> Result<String> {
        let salt = self.salt();
        Ok(self.argon2.hash_password(password, &salt)?.to_string())
    }

    /// Verifies a password.
    ///
    /// # Errors
    /// Returns an [`argon2::password_hash::Error`] if verification fails.
    pub fn verify_password(&mut self, password: &[u8], hash: &str) -> Result<()> {
        self.argon2.verify_password(password, &hash.try_into()?)
    }

    fn salt(&mut self) -> SaltString {
        SaltString::generate(&mut self.csprng)
    }
}

impl Default for PwHasher<'_, ChaCha20Rng> {
    fn default() -> Self {
        Self {
            csprng: ChaCha20Rng::from_entropy(),
            argon2: Argon2::default(),
        }
    }
}
