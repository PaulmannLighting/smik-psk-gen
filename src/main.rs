//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use argon2::Argon2;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use clap::Parser;
use clap_stdin::FileOrStdin;
pub use error::Error;
use log::error;
pub use password_hash_generator::PasswordHashGenerator;
use rand_chacha::ChaCha20Rng;

mod error;
mod password_hash_generator;
mod psk;

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
const DEFAULT_KEY_SIZE: usize = 14; // 112 bits are mandatory as per EN 18031.

#[derive(Parser)]
struct Args {
    #[arg(index = 1, help = "file of MAC addresses")]
    mac_list: FileOrStdin,
    #[arg(long, short, default_value_t = '\t', help = "column separator")]
    sep: char,
    #[arg(long, short, help = "print plain text PSK and hash in one single line")]
    inline: bool,
}

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();
    let Ok(mac_addresses) = args
        .mac_list
        .contents()
        .inspect_err(|error| error!("{error}"))
    else {
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
        if args.inline {
            println!(
                "{mac_address}{}{}{}{}",
                args.sep,
                psk.base64(),
                args.sep,
                psk.hash()
            );
        } else {
            println!("{mac_address}\t{}", psk.base64());
            eprintln!("{mac_address}\t{}", psk.hash());
        }
    }

    ExitCode::SUCCESS
}
