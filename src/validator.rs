use std::process::ExitCode;

use base64::Engine;
use log::{error, info};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier};

use crate::constants::BASE64;

/// Validator trait for validating PSKs against password hashes.
pub trait Validator {
    fn validate(&self, psk: String, hash: &str) -> ExitCode {
        self.validate_raw(
            &match BASE64.decode(psk) {
                Ok(psk) => psk,
                Err(error) => {
                    error!("Error decoding PSK: {error}");
                    return ExitCode::FAILURE;
                }
            },
            &match PasswordHash::new(hash) {
                Ok(hash) => hash,
                Err(error) => {
                    error!("Error parsing password hash: {error}");
                    return ExitCode::FAILURE;
                }
            },
        )
    }

    fn validate_raw(&self, psk: &[u8], hash: &PasswordHash<'_>) -> ExitCode;
}

impl<T> Validator for T
where
    T: PasswordHasher,
{
    fn validate_raw(&self, psk: &[u8], hash: &PasswordHash<'_>) -> ExitCode {
        if let Err(error) = self.verify_password(psk, hash) {
            error!("Password verification failed: {error}");
            ExitCode::FAILURE
        } else {
            info!("Password verification succeeded.");
            ExitCode::SUCCESS
        }
    }
}
