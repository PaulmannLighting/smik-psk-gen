mod argon2_hasher;
mod keygen;
mod password_verifier_ext;

use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub use argon2_hasher::Argon2Hasher;
pub use keygen::Keygen;
pub use password_verifier_ext::PasswordVerifierExt;
