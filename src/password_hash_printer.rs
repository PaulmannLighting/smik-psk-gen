use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use clap_stdin::FileOrStdin;

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
    pub fn generate_list(&mut self, mac_list: FileOrStdin) -> Result<(), Box<dyn Error>> {
        for (mac_address, result) in mac_list
            .contents()?
            .split_whitespace()
            .zip(&mut self.generator)
        {
            let psk = result?;

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

        Ok(())
    }

    /// Generate a specified amount of PSKs.
    pub fn generate_amount(&mut self, amount: usize) -> Result<(), Box<dyn Error>> {
        for result in (&mut self.generator).take(amount) {
            let psk = result?;

            if self.inline {
                println!("{}{}{}", psk.base64(), self.sep, psk.hash());
            } else {
                println!("{}", psk.base64());
                eprintln!("{}", psk.hash());
            }
        }

        Ok(())
    }
}
