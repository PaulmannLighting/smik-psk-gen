use std::process::ExitCode;

use argon2::{Argon2, PasswordHash};
use clap::Subcommand;
use log::error;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;

use self::target::Target;
use crate::constants::DEFAULT_KEY_SIZE;
use crate::password_hash_generator::PasswordHashGenerator;
use crate::password_hash_printer::PasswordHashPrinter;
use crate::psk::Psk;

mod target;

/// Actions to perform.
#[expect(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Action {
    /// Generate PSKs.
    Generate {
        #[arg(long, short, default_value_t = '\t', help = "Column separator")]
        sep: char,
        #[arg(long, short, help = "Print plain text PSK and hash in one single line")]
        inline: bool,
        #[clap(subcommand)]
        target: Target,
    },
    /// Validate the generated PSKs
    Validate {
        #[clap(help = "The base64-encoded PSK to validate.")]
        psk: String,
        #[clap(help = "The Argon2 hash.")]
        hash: PasswordHash,
    },
}

impl Action {
    /// Run the specified action.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let Ok(phg) =
            PasswordHashGenerator::<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2<'_>>::try_from_rng(
                &mut SysRng,
            )
            .inspect_err(|error| error!("{error}"))
        else {
            return ExitCode::FAILURE;
        };

        match self {
            Self::Generate {
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
            Self::Validate { psk, hash } => phg
                .verify(&Psk::new(psk, hash))
                .inspect_err(|error| eprintln!("{error}"))
                .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS),
        }
    }
}
