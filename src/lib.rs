mod keygen;
mod pw_hasher;

use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub use keygen::Keygen;
pub use pw_hasher::PwHasher;
