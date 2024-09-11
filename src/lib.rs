mod error;
mod password_hash_generator;

pub use error::Error;
pub use password_hash_generator::PasswordHashGenerator;

pub const DEFAULT_KEY_SIZE: usize = 12;
