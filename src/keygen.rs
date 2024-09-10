use rand_core::CryptoRngCore;

/// A trait for generating pre-shared keys.
pub trait Keygen: CryptoRngCore {
    /// Generate a pre-shared key of a given size.
    fn generate_key(&mut self, size: usize) -> Box<[u8]>;
}

impl<T> Keygen for T
where
    T: CryptoRngCore,
{
    #[must_use]
    fn generate_key(&mut self, size: usize) -> Box<[u8]> {
        let mut result = vec![0; size];
        self.fill_bytes(&mut result);
        result.into_boxed_slice()
    }
}
