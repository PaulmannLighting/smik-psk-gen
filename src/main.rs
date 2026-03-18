//! Generate a PSK for each MAC address in a list.

use std::process::ExitCode;

use clap::Parser;

use self::args::Args;

mod args;
mod constants;
mod error;
mod password_hash_generator;
mod password_hash_printer;
mod psk;

fn main() -> ExitCode {
    env_logger::init();
    Args::parse().run()
}
