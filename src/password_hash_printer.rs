use std::process::ExitCode;

use clap_stdin::FileOrStdin;
use log::error;
use password_hash::rand_core::CryptoRng;
use password_hash::PasswordHasher;

use crate::password_hash_generator::PasswordHashGenerator;

/// Print generated passwords.
pub struct PasswordHashPrinter<const SIZE: usize, R, H> {
    generator: PasswordHashGenerator<SIZE, R, H>,
    sep: char,
    inline: bool,
}

impl<const SIZE: usize, R, H> PasswordHashPrinter<SIZE, R, H> {
    /// Create a new [`PasswordHashPrinter`] with a password hash generator.
    #[must_use]
    pub const fn new(
        generator: PasswordHashGenerator<SIZE, R, H>,
        sep: char,
        inline: bool,
    ) -> Self {
        Self {
            generator,
            sep,
            inline,
        }
    }
}

impl<const SIZE: usize, R, H> PasswordHashPrinter<SIZE, R, H>
where
    R: CryptoRng,
    H: PasswordHasher,
{
    /// Generate PSKs for each MAC address in the list.
    pub fn generate_list(&mut self, mac_list: FileOrStdin) -> ExitCode {
        let Ok(mac_addresses) = mac_list.contents().inspect_err(|error| error!("{error}")) else {
            return ExitCode::FAILURE;
        };

        for (mac_address, psk) in mac_addresses.split_whitespace().zip(&mut self.generator) {
            if self.inline {
                println!(
                    "{mac_address}{}{}{}{}",
                    self.sep,
                    psk.base64(),
                    self.sep,
                    psk.hash()
                );
            } else {
                println!("{mac_address}{}{}", self.sep, psk.base64());
                eprintln!("{mac_address}{}{}", self.sep, psk.hash());
            }
        }

        ExitCode::SUCCESS
    }

    /// Generate a specified amount of PSKs.
    pub fn generate_amount(&mut self, amount: usize) -> ExitCode {
        for (_, psk) in (0..amount).zip(&mut self.generator) {
            if self.inline {
                println!("{}{}{}", psk.base64(), self.sep, psk.hash());
            } else {
                println!("{}", psk.base64());
                eprintln!("{}", psk.hash());
            }
        }

        ExitCode::SUCCESS
    }
}
