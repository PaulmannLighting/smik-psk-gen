use rand_core::{CryptoRng, RngCore};
use std::mem::zeroed;

const KEY_SIZE: usize = 12;

pub fn generate_psk<R>(csprng: &mut R) -> [u8; KEY_SIZE]
where
    R: CryptoRng + RngCore,
{
    let mut bytes = unsafe { [zeroed(); KEY_SIZE] };

    for (index, byte) in csprng
        .next_u32()
        .to_le_bytes()
        .into_iter()
        .chain(csprng.next_u32().to_le_bytes())
        .chain(csprng.next_u32().to_le_bytes())
        .enumerate()
    {
        bytes[index] = byte;
    }

    bytes
}
