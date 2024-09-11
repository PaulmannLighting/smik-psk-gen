use argon2::Argon2;
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rand_chacha::ChaCha20Rng;
use smik_psk_gen::{PasswordHashGenerator, DEFAULT_KEY_SIZE};
use std::process::exit;

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
    let mac_addresses = args.mac_list.contents().unwrap_or_else(|error| {
        error!("{error}");
        exit(1)
    });

    for (mac_address, (b64key, hash)) in mac_addresses
        .split_whitespace()
        .zip(PasswordHashGenerator::<DEFAULT_KEY_SIZE, ChaCha20Rng, Argon2>::default())
    {
        println!("{mac_address}\t{b64key}");
        eprintln!("{mac_address}\t{hash}");
    }
}
