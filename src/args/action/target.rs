use clap::Subcommand;
use clap_stdin::FileOrStdin;

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
