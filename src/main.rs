use argon2::{password_hash::SaltString, Argon2, PasswordHasher, PasswordVerifier};
use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
    Engine,
};
use clap::Parser;
use log::error;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use smik_psk_gen::generate_psk;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::process::exit;

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

#[derive(Parser)]
struct Args {
    #[arg(index = 1, help = "file of MAC addresses")]
    mac_list: PathBuf,
    #[arg(long, short, default_value_t = '\t', help = "column separator")]
    sep: char,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let mac_addresses = read_to_string(args.mac_list).unwrap_or_else(|error| {
        error!("{error}");
        exit(1)
    });
    let mut csprng = ChaCha20Rng::from_entropy();
    let argon2 = Argon2::default();

    for mac_address in mac_addresses.split_whitespace() {
        let psk = generate_psk(&mut csprng);
        let b64key = BASE64.encode(psk);
        let salt = SaltString::generate(&mut csprng);
        let hash = argon2
            .hash_password(&psk, &salt)
            .expect("could not hash key");
        assert!(argon2
            .verify_password(&BASE64.decode(&b64key).expect("invalid base64 hash"), &hash)
            .is_ok());
        println!("{mac_address}\t{b64key}");
        eprintln!("{mac_address}\t{hash}");
    }
}
