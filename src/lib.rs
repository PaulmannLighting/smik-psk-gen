extern crate core;

mod password_verifier_ext;
mod salt_generator;
mod salt_string_ext;

use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub use password_verifier_ext::{Error, PasswordVerifierExt};
pub use salt_generator::SaltGenerator;
pub use salt_string_ext::SaltStringExt;
