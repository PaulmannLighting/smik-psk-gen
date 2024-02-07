use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

#[derive(Debug)]
pub struct Keygen<R>
where
    R: CryptoRngCore,
{
    csprng: R,
}

impl<R> Keygen<R>
where
    R: CryptoRngCore,
{
    #[must_use]
    pub const fn new(csprng: R) -> Self {
        Self { csprng }
    }

    #[must_use]
    pub fn generate_psk(&mut self, size: usize) -> Box<[u8]>
    where
        R: CryptoRngCore,
    {
        let mut result = vec![0; size];
        self.csprng.fill_bytes(&mut result);
        result.into_boxed_slice()
    }
}

impl Default for Keygen<ChaCha20Rng> {
    fn default() -> Self {
        Self::new(ChaCha20Rng::from_entropy())
    }
}
