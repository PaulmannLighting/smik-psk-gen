use password_hash::SaltString;
use rand_core::CryptoRngCore;

/// Generate a random salt.
pub trait SaltGenerator: CryptoRngCore {
    fn generate_salt(&mut self) -> SaltString;
}

impl<T> SaltGenerator for T
where
    T: CryptoRngCore,
{
    fn generate_salt(&mut self) -> SaltString {
        SaltString::generate(self)
    }
}
