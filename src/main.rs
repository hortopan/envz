mod biometric;
mod cli;
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

    let result = match cli.command {
        Commands::Init {
            file,
            no_biometric,
            force,
        } => commands::init::execute(file, !no_biometric, force),
        Commands::Run { command } => commands::run::execute(&command),
        Commands::Unsafe { command } => commands::unsafe_cmd::execute(&command),
        Commands::Set { pair } => commands::set::execute(&pair),
        Commands::Get { key } => commands::get::execute(&key),
        Commands::Delete { key } => commands::delete::execute(&key),
        Commands::List => commands::list::execute(),
        Commands::Env => commands::env::execute(),
        Commands::Unenv => commands::unenv::execute(),
        Commands::Clear => commands::clear::execute(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
