use crate::Error;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use base64::Engine;
use password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use rand_core::{CryptoRngCore, SeedableRng};

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

pub struct PasswordHashGenerator<const KEY_SIZE: usize, R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    csprng: R,
    hasher: H,
    buffer: [u8; KEY_SIZE],
}

impl<const KEY_SIZE: usize, R, H> PasswordHashGenerator<KEY_SIZE, R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    #[must_use]
    pub const fn new(csprng: R, hasher: H) -> Self {
        Self {
            csprng,
            hasher,
            buffer: [0; KEY_SIZE],
        }
    }

    /// Generates a random password and writes it into the buffer returning its BASE64 encoding.
    ///
    /// # Errors
    /// Returns a [`password_hash::Error`] if the password hash could not be generated.
    pub fn generate(&mut self) -> Result<(String, String), Error> {
        let b64 = self.generate_psk();
        let hash = self.hash_psk()?;
        self.reset();
        self.verify(&b64, &hash)?;
        Ok((b64, hash))
    }

    /// Generate a new pre-shared key.
    fn generate_psk(&mut self) -> String {
        self.csprng.fill_bytes(&mut self.buffer);
        BASE64.encode(self.buffer)
    }

    /// Hash the pre-shared key.
    fn hash_psk(&mut self) -> password_hash::Result<String> {
        let salt = SaltString::generate(&mut self.csprng);
        self.hasher
            .hash_password(&self.buffer, &salt)
            .map(|hash| hash.to_string())
    }

    /// Reset the buffer to all zeros.
    fn reset(&mut self) {
        self.buffer.fill(0);
    }

    /// Verify a password hash.
    ///
    /// # Errors
    /// Returns an [`Error`] if the password hash could not be verified.
    fn verify(&self, b64key: &str, hash: &str) -> Result<(), Error> {
        Ok(self
            .hasher
            .verify_password(&BASE64.decode(b64key)?, &hash.try_into()?)?)
    }
}

impl<const KEY_SIZE: usize, R, H> Default for PasswordHashGenerator<KEY_SIZE, R, H>
where
    R: CryptoRngCore + SeedableRng,
    H: PasswordHasher + Default,
{
    fn default() -> Self {
        Self::new(R::from_entropy(), H::default())
    }
}

impl<const KEY_SIZE: usize, R, H> Iterator for PasswordHashGenerator<KEY_SIZE, R, H>
where
    R: CryptoRngCore,
    H: PasswordHasher,
{
    type Item = (String, String);

    fn next(&mut self) -> Option<Self::Item> {
        self.generate().ok()
    }
}
