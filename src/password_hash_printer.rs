use std::process::ExitCode;

use clap_stdin::FileOrStdin;
use log::error;

use crate::error::Error;
use crate::psk::Psk;

/// Print generated passwords.
pub struct PasswordHashPrinter<T> {
    generator: T,
    sep: char,
    inline: bool,
}

impl<T> PasswordHashPrinter<T> {
    /// Create a new [`PasswordHashPrinter`] with a password hash generator.
    #[must_use]
    pub const fn new(generator: T, sep: char, inline: bool) -> Self {
        Self {
            generator,
            sep,
            inline,
        }
    }
}

impl<T> PasswordHashPrinter<T>
where
    T: Iterator<Item = Result<Psk, Error>>,
{
    /// Generate PSKs for each MAC address in a list separated by whitespace.
    pub fn generate_list(&mut self, mac_list: FileOrStdin) -> ExitCode {
        let Ok(mac_addresses) = mac_list.contents().inspect_err(|error| error!("{error}")) else {
            return ExitCode::FAILURE;
        };

        for (mac_address, result) in mac_addresses.split_whitespace().zip(&mut self.generator) {
            let Ok(psk) = result.inspect_err(|error| error!("{error}")) else {
                return ExitCode::FAILURE;
            };

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
        for result in (&mut self.generator).take(amount) {
            let Ok(psk) = result.inspect_err(|error| error!("{error}")) else {
                return ExitCode::FAILURE;
            };

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
