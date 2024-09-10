use rand_core::CryptoRngCore;

pub trait Keygen: CryptoRngCore {
    fn generate_psk(&mut self, size: usize) -> Box<[u8]>;
}

impl<T> Keygen for T
where
    T: CryptoRngCore,
{
    #[must_use]
    fn generate_psk(&mut self, size: usize) -> Box<[u8]> {
        let mut result = vec![0; size];
        self.fill_bytes(&mut result);
        result.into_boxed_slice()
    }
}
