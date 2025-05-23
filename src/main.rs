mod cli;
pub mod config;
mod errors;
mod wallet;

use clap::Parser;
use cli::{Cli, Commands};
use std::process;
use wallet::Wallet;

fn main() {
    let cli = Cli::parse();

    // Load config (adjust path or logic as needed)
    let config = match bitvmx_settings::settings::load_config_file::<crate::config::Config>(Some(
        "config/regtest.yaml".to_string(),
    )) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            process::exit(1);
        }
    };

    let wallet = match Wallet::new(config) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Failed to initialize wallet: {e}");
            process::exit(1);
        }
    };

    match &cli.command {
        Commands::CreateKey { identifier, index } => {
            match wallet.create_secret_key(identifier, *index) {
                Ok(pk) => println!("Created key: {pk}"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::ImportKey {
            identifier,
            secret_key,
        } => match wallet.import_secret_key(identifier, secret_key) {
            Ok(_) => println!("Imported key for {identifier}"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::AddFunding {
            identifier,
            funding_id,
            outpoint,
            amount,
        } => {
            let outpoint = match outpoint.parse() {
                Ok(op) => op,
                Err(e) => {
                    eprintln!("Invalid outpoint: {e}");
                    process::exit(1);
                }
            };
            match wallet.add_funding(identifier, funding_id, outpoint, *amount) {
                Ok(_) => println!("Added funding"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::RemoveFunding {
            identifier,
            funding_id,
        } => match wallet.remove_funding(identifier, funding_id) {
            Ok(_) => println!("Removed funding"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::FundAddress {
            identifier,
            funding_id,
            to_pubkey,
            amount,
            fee,
        } => {
            let to_pubkey = match to_pubkey.parse() {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!("Invalid public key: {e}");
                    process::exit(1);
                }
            };
            match wallet.fund_address(identifier, funding_id, to_pubkey, *amount, *fee) {
                Ok(txid) => println!("Funded address, txid: {txid}"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::ConfirmTransfer {
            identifier,
            funding_id,
        } => match wallet.confirm_transfer(identifier, funding_id) {
            Ok(_) => println!("Transfer confirmed"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::RevertTransfer {
            identifier,
            funding_id,
        } => match wallet.revert_transfer(identifier, funding_id) {
            Ok(_) => println!("Transfer reverted"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::ListFunds { identifier } => match wallet.list_funds(identifier) {
            Ok(funds) => {
                for (funding_id, outpoint, amount) in funds {
                    println!("Funding ID: {funding_id}, OutPoint: {outpoint}, Amount: {amount}");
                }
            }
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::Mine { num_blocks } => match wallet.mine(*num_blocks) {
            Ok(_) => println!("Mined {num_blocks} blocks"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::RegtestFund {
            identifier,
            funding_id,
            amount,
        } => match wallet.regtest_fund(identifier, funding_id, *amount) {
            Ok(_) => println!("Regtest funded"),
            Err(e) => eprintln!("Error: {e}"),
        },
    }
}
