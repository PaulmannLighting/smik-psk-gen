use std::process::exit;

use base64::Engine;
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use smik_psk_gen::{Keygen, PwHasher, BASE64};

pub const DEFAULT_KEY_SIZE: usize = 12;

#[derive(Parser)]
struct Args {
    #[arg(index = 1, help = "file of MAC addresses")]
    mac_list: FileOrStdin,
    #[arg(long, short, default_value_t = '\t', help = "column separator")]
    sep: char,
    #[arg(long, short, default_value_t = DEFAULT_KEY_SIZE, help = "key size in bytes")]
    key_size: usize,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let mac_addresses = args.mac_list.contents().unwrap_or_else(|error| {
        error!("{error}");
        exit(1)
    });
    let mut keygen = ChaCha20Rng::from_entropy();
    let mut pw_hasher = PwHasher::<ChaCha20Rng>::default();

    for mac_address in mac_addresses.split_whitespace() {
        let psk = keygen.generate_psk(args.key_size);
        let b64key = BASE64.encode(&psk);
        let hash = pw_hasher.hash(&psk).expect("could not hash key");
        assert!(pw_hasher
            .verify_password(&BASE64.decode(&b64key).expect("invalid base64 hash"), &hash)
            .is_ok());
        println!("{mac_address}\t{b64key}");
        eprintln!("{mac_address}\t{hash}");
    }
}
