//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use argon2::{Argon2, PasswordHash};
use clap::Parser;
use log::error;
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

fn main() -> ExitCode {
    env_logger::init();

    match Args::parse().action {
        Action::Generate {
            target,
            sep,
            inline,
        } => {
            let Ok(phg) = PasswordHashGenerator::<
                DEFAULT_KEY_SIZE,
                ChaCha20Rng,
                Argon2<'_>,
                PasswordHash,
            >::try_from_rng(&mut SysRng)
            .inspect_err(|error| error!("{error}")) else {
                return ExitCode::FAILURE;
            };

            let mut printer = PasswordHashPrinter::new(phg, sep, inline);

            match target {
                Target::List { mac_list } => printer.generate_list(mac_list),
                Target::Amount { amount } => printer.generate_amount(amount),
            }
        }
        Action::Validate { psk, hash } => Argon2::default()
            .verify_password(&psk, &hash)
            .inspect_err(|error| error!("{error}"))
            .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS),
    }
}
