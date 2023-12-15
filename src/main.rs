use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{
    alphabet::STANDARD,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
    Engine,
};
use clap::Parser;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use smik_psk_gen::generate_psk;

const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

#[derive(Parser)]
struct Args {
    #[arg(index = 1, default_value_t = 1)]
    amount: u16,
}

fn main() {
    let args = Args::parse();
    let mut csprng = ChaCha20Rng::from_entropy();
    let argon2 = Argon2::default();

    for _ in 0..args.amount {
        let psk = generate_psk(&mut csprng);
        let b64key = BASE64.encode(psk);
        let salt = SaltString::generate(&mut csprng);
        let hash = argon2
            .hash_password(&psk, &salt)
            .expect("could not hash key");
        println!("{b64key}\t{hash}");
    }
}
