use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};
use rand_core::{CryptoRng, RngCore};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub const KEY_SIZE: usize = 12;

/// Generate a new PSK.
pub fn generate_psk<const SIZE: usize, R>(csprng: &mut R) -> [u8; SIZE]
where
    R: CryptoRng + RngCore,
{
    let mut result = [0; SIZE];
    csprng.fill_bytes(&mut result);
    result
}
