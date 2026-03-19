//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use argon2::{Argon2, PasswordHash};
use clap::Parser;
use log::error;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;

use self::args::{Action, Args, Target};
use self::constants::DEFAULT_KEY_SIZE;
use self::password_hash_generator::PasswordHashGenerator;
use self::password_hash_printer::PasswordHashPrinter;
use self::psk::Psk;

mod args;
mod constants;
mod password_hash_generator;
mod password_hash_printer;
mod psk;

fn main() -> ExitCode {
    env_logger::init();

    let Ok(phg) = PasswordHashGenerator::<
        DEFAULT_KEY_SIZE,
        ChaCha20Rng,
        Argon2<'_>,
        PasswordHash,
    >::try_from_rng(&mut SysRng)
        .inspect_err(|error| error!("{error}")) else {
        return ExitCode::FAILURE;
    };

    match Args::parse().action {
        Action::Generate {
            target,
            sep,
            inline,
        } => {
            let mut printer = PasswordHashPrinter::new(phg, sep, inline);
            match target {
                Target::List { mac_list } => printer.generate_list(mac_list),
                Target::Amount { amount } => printer.generate_amount(amount),
            }
        }
        Action::Validate { psk, hash } => {
            let Ok(psk) =
                Psk::try_from_base64_and_hash(&psk, hash).inspect_err(|error| eprintln!("{error}"))
            else {
                return ExitCode::FAILURE;
            };

            phg.verify(&psk)
                .inspect_err(|error| eprintln!("{error}"))
                .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS)
        }
    }
}
