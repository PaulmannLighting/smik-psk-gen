mod hasher;
mod password_verifier_ext;

use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub use hasher::Hasher;
pub use password_verifier_ext::{Error, PasswordVerifierExt};
