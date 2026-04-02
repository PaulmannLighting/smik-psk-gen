//! Generate a PSK for each MAC address in a list.

use std::error::Error;

use argon2::{Argon2, PasswordHash};
use clap::Parser;
use password_hash::PasswordVerifier;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;

use self::args::{Action, Args, Target};
use self::constants::DEFAULT_KEY_SIZE;
use self::password_hash_generator::PasswordHashGenerator;
use self::password_hash_printer::PasswordHashPrinter;

mod args;
mod base64_key;
mod constants;
mod password_hash_generator;
mod password_hash_printer;
mod psk;

type DefaultPhg<'key> =
    PasswordHashGenerator<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2<'key>, PasswordHash>;

fn main() -> Result<(), Box<dyn Error>> {
    match Args::parse().action {
        Action::Generate {
            target,
            sep,
            inline,
        } => {
            let mut printer =
                PasswordHashPrinter::new(DefaultPhg::try_from_rng(&mut SysRng)?, sep, inline);

            match target {
                Target::List { mac_list } => printer.generate_list(mac_list),
                Target::Amount { amount } => printer.generate_amount(amount),
            }
        }
        Action::Validate { psk, hash } => Argon2::default()
            .verify_password(&psk, &hash)
            .map_err(Into::into),
    }
}
