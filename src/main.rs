use argon2::Argon2;
use base64::Engine;
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use smik_psk_gen::{Argon2Hasher, Keygen, PasswordVerifierExt, BASE64};
use std::process::exit;

pub const DEFAULT_KEY_SIZE: usize = 12;

#[derive(Parser)]
struct Args {
    #[arg(index = 1, help = "file of MAC addresses")]
    mac_list: FileOrStdin,
    #[arg(long, short, default_value_t = '\t', help = "column separator")]
    sep: char,
    #[arg(long, short, default_value_t = DEFAULT_KEY_SIZE, help = "key size in bytes")]
    key_size: usize,
    #[arg(long, short, help = "validate generated keys")]
    validate: bool,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let mac_addresses = args.mac_list.contents().unwrap_or_else(|error| {
        error!("{error}");
        exit(1)
    });
    let mut csprng = ChaCha20Rng::from_entropy();
    let argon2 = Argon2::default();

    for mac_address in mac_addresses.split_whitespace() {
        let psk = csprng.generate_key(args.key_size);
        let b64key = BASE64.encode(&psk);
        let hash = csprng
            .hash_argon2(&argon2, &psk)
            .expect("could not hash key");

        if args.validate {
            assert!(argon2.verify_base64(&b64key, &hash).is_ok());
        }

        println!("{mac_address}\t{b64key}");
        eprintln!("{mac_address}\t{hash}");
    }
}
