use std::process::ExitCode;

use argon2::Argon2;
use clap::Subcommand;
use rand_chacha::ChaCha20Rng;

use self::target::Target;
use crate::constants::DEFAULT_KEY_SIZE;
use crate::password_hash_generator::PasswordHashGenerator;
use crate::password_hash_printer::PasswordHashPrinter;
use crate::validator::Validator;

mod target;

/// Actions to perform.
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
        hash: String,
    },
}

impl Action {
    /// Run the specified action.
    #[must_use]
    pub fn run(self) -> ExitCode {
        match self {
            Self::Generate {
                target,
                sep,
                inline,
            } => {
                let mut printer =
                    PasswordHashPrinter::<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2<'_>>::new(
                        PasswordHashGenerator::default(),
                        sep,
                        inline,
                    );
                match target {
                    Target::List { mac_list } => printer.generate_list(mac_list),
                    Target::Amount { amount } => printer.generate_amount(amount),
                }
            }
            Self::Validate { psk, hash } => Argon2::default().validate(psk, &hash),
        }
    }
}
