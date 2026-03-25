#[macro_use]
extern crate litcrypt;

use_litcrypt!();

mod biometric;
mod cli;
mod codesign;
mod commands;
mod crypto;
mod env_filter;
mod error;
mod keychain;
mod store;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    let vault_path = cli.vault.as_deref();

    let result = match cli.command {
        Commands::Init { file, force } => commands::init::execute(file, force, vault_path),
        Commands::Run { command } => commands::run::execute(&command, vault_path),
        Commands::Unsafe { command } => commands::unsafe_cmd::execute(&command),
        Commands::Set { pair } => commands::set::execute(&pair, vault_path),
        Commands::Get { key } => commands::get::execute(&key, vault_path),
        Commands::Delete { key } => commands::delete::execute(&key, vault_path),
        Commands::List => commands::list::execute(vault_path),
        Commands::Env => commands::env::execute(vault_path),
        Commands::Unenv => commands::unenv::execute(vault_path),
        Commands::Clear => commands::clear::execute(vault_path),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
