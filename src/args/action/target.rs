use clap::Subcommand;
use clap_stdin::FileOrStdin;

/// Target for PSK generation.
#[derive(Subcommand)]
pub enum Target {
    /// Generate PSKs for each MAC address in the list
    List {
        #[clap(help = "File containing MAC addresses, one per line. Use '-' or omit for stdin.")]
        mac_list: FileOrStdin,
    },
    /// Generate a specified amount of PSKs
    Amount {
        #[clap(help = "Number of PSKs to generate.")]
        amount: usize,
    },
}
