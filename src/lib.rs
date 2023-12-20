use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};
use rand_core::{CryptoRng, RngCore};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

#[derive(Debug)]
pub struct Keygen {
    size: usize,
}

impl Keygen {
    #[must_use]
    pub const fn new(size: usize) -> Self {
        Self { size }
    }

    #[must_use]
    pub fn generate_psk<R>(&self, csprng: &mut R) -> Vec<u8>
    where
        R: CryptoRng + RngCore,
    {
        let mut result = vec![0; self.size];
        csprng.fill_bytes(&mut result);
        result
    }
}
