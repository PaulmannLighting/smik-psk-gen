mod error;
mod password_hash_generator;

use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub use error::Error;
pub use password_hash_generator::PasswordHashGenerator;
