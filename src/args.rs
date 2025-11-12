use std::process::ExitCode;

use clap::Parser;

use self::action::Action;

mod action;

/// Command line arguments.
#[derive(Parser)]
pub struct Args {
    #[clap(subcommand)]
    action: Action,
}

impl Args {
    /// Run the specified action.
    #[must_use]
    pub fn run(self) -> ExitCode {
        self.action.run()
    }
}
