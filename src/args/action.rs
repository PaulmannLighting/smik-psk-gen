use argon2::PasswordHash;
use clap::Subcommand;

pub use self::target::Target;

mod target;

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
        psk: String,
        #[clap(help = "The Argon2 hash.")]
        hash: PasswordHash,
    },
}
