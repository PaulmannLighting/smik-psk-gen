use password_hash::{PasswordHasher, SaltString};
use rand_core::CryptoRngCore;

pub struct PwHasher<'a, R, P>
where
    R: CryptoRngCore,
    P: PasswordHasher,
{
    csprng: &'a mut R,
    password_hasher: &'a P,
}

impl<'a, R, P> PwHasher<'a, R, P>
where
    R: CryptoRngCore,
    P: PasswordHasher,
{
    #[must_use]
    pub fn new(csprng: &'a mut R, password_hasher: &'a P) -> Self {
        Self {
            csprng,
            password_hasher,
        }
    }

    /// Hash a password.
    pub fn hash(self, password: &[u8]) -> password_hash::Result<String> {
        Ok(self
            .password_hasher
            .hash_password(password, &SaltString::generate(self.csprng))?
            .to_string())
    }
}
