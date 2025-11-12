//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use argon2::Argon2;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use clap::{Parser, Subcommand};
use clap_stdin::FileOrStdin;
use log::error;
use rand_chacha::ChaCha20Rng;

use self::error::Error;
use self::password_hash_generator::PasswordHashGenerator;

mod error;
mod password_hash_generator;
mod psk;

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
}

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();
    let sep = args.sep;
    let inline = args.inline;

    match args.target {
        Target::List { mac_list } => generate_list(mac_list, sep, inline),
        Target::Amount { amount } => generate_amount(amount, sep, inline),
    }
}

fn generate_list(mac_list: FileOrStdin, sep: char, inline: bool) -> ExitCode {
    let Ok(mac_addresses) = mac_list.contents().inspect_err(|error| error!("{error}")) else {
        return ExitCode::FAILURE;
    };

    for (mac_address, psk) in mac_addresses
        .split_whitespace()
        .zip(PasswordHashGenerator::<
            DEFAULT_KEY_SIZE,
            ChaCha20Rng,
            Argon2<'_>,
        >::default())
    {
        if inline {
            println!("{mac_address}{sep}{}{sep}{}", psk.base64(), psk.hash());
        } else {
            println!("{mac_address}{sep}{}", psk.base64());
            eprintln!("{mac_address}{sep}{}", psk.hash());
        }
    }

    ExitCode::SUCCESS
}

fn generate_amount(amount: usize, sep: char, inline: bool) -> ExitCode {
    for (_, psk) in (0..amount).zip(PasswordHashGenerator::<
        DEFAULT_KEY_SIZE,
        ChaCha20Rng,
        Argon2<'_>,
    >::default())
    {
        if inline {
            println!("{}{sep}{}", psk.base64(), psk.hash());
        } else {
            println!("{}", psk.base64());
            eprintln!("{}", psk.hash());
        }
    }

    ExitCode::SUCCESS
}
