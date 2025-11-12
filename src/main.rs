//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use argon2::Argon2;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use clap::{Parser, Subcommand};
use clap_stdin::FileOrStdin;
use rand_chacha::ChaCha20Rng;

use self::error::Error;
use self::password_hash_generator::PasswordHashGenerator;
use self::password_hash_printer::PasswordHashPrinter;
use self::validator::Validator;

mod error;
mod password_hash_generator;
mod password_hash_printer;
mod psk;
mod validator;

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
const DEFAULT_KEY_SIZE: usize = 14; // 112 bits are mandatory as per EN 18031.

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    target: Target,
    #[arg(long, short, default_value_t = '\t', help = "Column separator")]
    sep: char,
    #[arg(long, short, help = "Print plain text PSK and hash in one single line")]
    inline: bool,
}

#[derive(Subcommand)]
enum Target {
    /// Generate PSKs for each MAC address in the list
    List {
        #[clap(help = "File containing MAC addresses, one per line. Use '-' or omit for stdin.")]
        mac_list: FileOrStdin,
    },
    /// Generate a specified amount of PSKs
    Amount {
        #[clap(help = "Number of PSKs to generate.")]
        amount: usize,
    },
    /// Validate the generated PSKs
    Validate {
        #[clap(help = "The base64-encoded PSK to validate.")]
        psk: String,
        #[clap(help = "The Argon2 hash.")]
        hash: String,
    },
}

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();
    let sep = args.sep;
    let inline = args.inline;

    match args.target {
        Target::List { mac_list } => PasswordHashPrinter::new(
            PasswordHashGenerator::<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2<'_>>::default(),
            sep,
            inline,
        )
        .generate_list(mac_list),
        Target::Amount { amount } => PasswordHashPrinter::new(
            PasswordHashGenerator::<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2<'_>>::default(),
            sep,
            inline,
        )
        .generate_amount(amount),
        Target::Validate { psk, hash } => Argon2::default().validate(psk, &hash),
    }
}
