use clap::Parser;

pub use self::action::{Action, Target};

mod action;

/// Command line arguments.
#[derive(Parser)]
pub struct Args {
    #[clap(subcommand)]
    pub(crate) action: Action,
}
