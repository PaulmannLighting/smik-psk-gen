use argon2::PasswordHash;
use clap::{Parser, Subcommand};
use clap_stdin::FileOrStdin;

use crate::base64_key::Base64Key;

/// Command line arguments.
#[derive(Parser)]
pub struct Args {
    #[clap(subcommand)]
    pub(crate) action: Action,
}

/// Actions to perform.
#[expect(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Action {
    /// Generate PSKs.
    Generate {
        #[arg(long, short, default_value_t = '\t', help = "Column separator")]
        sep: char,
        #[arg(long, short, help = "Print plain text PSK and hash in one single line")]
        inline: bool,
        #[clap(subcommand)]
        target: Target,
    },
    /// Validate the generated PSKs
    Validate {
        #[clap(help = "The base64-encoded PSK to validate.")]
        psk: Base64Key,
        #[clap(help = "The Argon2 hash.")]
        hash: PasswordHash,
    },
}

/// Target for PSK generation.
#[derive(Subcommand)]
pub enum Target {
    /// Generate PSKs for each MAC address in the list
    List {
        #[clap(help = "File containing MAC addresses, separated by whitespace.")]
        mac_list: FileOrStdin,
    },
    /// Generate a specified amount of PSKs
    Amount {
        #[clap(help = "Number of PSKs to generate.")]
        amount: usize,
    },
}
