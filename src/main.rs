//! Generate a PSK for each MAC address in a list.

use std::process::exit;

use argon2::Argon2;
use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rand_chacha::ChaCha20Rng;

pub use error::Error;
pub use password_hash_generator::PasswordHashGenerator;

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
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let Ok(mac_addresses) = args
        .mac_list
        .contents()
        .inspect_err(|error| error!("{error}"))
    else {
        exit(1)
    };

    for (mac_address, psk) in mac_addresses
        .split_whitespace()
        .zip(PasswordHashGenerator::<
            DEFAULT_KEY_SIZE,
            ChaCha20Rng,
            Argon2<'_>,
        >::default())
    {
        println!("{mac_address}\t{}", psk.base64());
        eprintln!("{mac_address}\t{}", psk.hash());
    }
}
