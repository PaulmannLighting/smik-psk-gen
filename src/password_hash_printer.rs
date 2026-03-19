use std::fmt::Display;
use std::marker::PhantomData;
use std::process::ExitCode;

use clap_stdin::FileOrStdin;
use log::error;

use crate::psk::Psk;

/// Print generated passwords.
pub struct PasswordHashPrinter<T, P> {
    generator: T,
    sep: char,
    inline: bool,
    _phantom: PhantomData<P>,
}

impl<T, P> PasswordHashPrinter<T, P> {
    /// Create a new [`PasswordHashPrinter`] with a password hash generator.
    #[must_use]
    pub const fn new(generator: T, sep: char, inline: bool) -> Self {
        Self {
            generator,
            sep,
            inline,
            _phantom: PhantomData,
        }
    }
}

impl<T, P> PasswordHashPrinter<T, P>
where
    T: Iterator<Item = password_hash::Result<Psk<P>>>,
    P: Display,
{
    /// Generate PSKs for each MAC address in a list separated by whitespace.
    #[must_use]
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
    #[must_use]
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
