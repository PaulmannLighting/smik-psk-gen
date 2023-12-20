use argon2::{password_hash::SaltString, Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use clap::Parser;
use log::error;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use smik_psk_gen::{Keygen, BASE64};
use std::fs::read_to_string;
use std::path::PathBuf;
use std::process::exit;

pub const DEFAULT_KEY_SIZE: usize = 12;

#[derive(Parser)]
struct Args {
    #[arg(index = 1, help = "file of MAC addresses")]
    mac_list: PathBuf,
    #[arg(long, short, default_value_t = '\t', help = "column separator")]
    sep: char,
    #[arg(long, short, default_value_t = DEFAULT_KEY_SIZE, help = "key size in bytes")]
    key_size: usize,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let mac_addresses = read_to_string(args.mac_list).unwrap_or_else(|error| {
        error!("{error}");
        exit(1)
    });
    let mut csprng = ChaCha20Rng::from_entropy();
    let keygen = Keygen::new(args.key_size);
    let argon2 = Argon2::default();

    for mac_address in mac_addresses.split_whitespace() {
        let psk = keygen.generate_psk(&mut csprng);
        let b64key = BASE64.encode(psk.as_slice());
        let salt = SaltString::generate(&mut csprng);
        let hash = argon2
            .hash_password(psk.as_slice(), &salt)
            .expect("could not hash key");
        assert!(argon2
            .verify_password(&BASE64.decode(&b64key).expect("invalid base64 hash"), &hash)
            .is_ok());
        println!("{mac_address}\t{b64key}");
        eprintln!("{mac_address}\t{hash}");
    }
}
