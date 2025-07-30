mod cli;
pub mod config;
pub mod errors;
pub mod old_wallet;

use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
use std::process;
use tracing_subscriber::EnvFilter;
use old_wallet::Wallet;

fn config_trace() {
    let default_modules = ["info"];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

fn main() {
    let cli = Cli::parse();

    // Use the config file specified by the user
    let config =
        match bitvmx_settings::settings::load_config_file::<Config>(Some(cli.config.clone()))
        {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to load config: {e}");
                process::exit(1);
            }
        };
    config_trace();

    let init_client = match &cli.command {
        Commands::BtcToSat { .. } => false,
        _ => true,
    };

    let wallet = match Wallet::new(config, init_client) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Failed to initialize wallet: {e}");
            process::exit(1);
        }
    };

    match &cli.command {
        Commands::CreateWallet { identifier } => match wallet.create_wallet(identifier) {
            Ok(pk) => println!("Created key: {pk}"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::ImportKey {
            identifier,
            secret_key,
        } => match wallet.create_wallet_from_secret(identifier, secret_key) {
            Ok(_) => println!("Imported key for {identifier}"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::ExportWallet { identifier } => match wallet.export_wallet(identifier) {
            Ok((pubkey, secret_key)) => {
                println!("Wallet {identifier}:");
                println!(" - Pubkey: {pubkey}");
                println!(" - Secret key: {secret_key}");
            }
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
            taproot: output_is_taproot,
            confirm,
        } => {
            let to_pubkey = match to_pubkey.parse() {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!("Invalid public key: {e}");
                    process::exit(1);
                }
            };
            match wallet.fund_address(
                identifier,
                funding_id,
                to_pubkey,
                &amount,
                *fee,
                *output_is_taproot,
                *confirm,
                None,
            ) {
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
        Commands::BtcToSat { btc } => {
            let amount = bitcoin::Amount::from_btc(*btc).unwrap();
            let sats = amount.to_sat();
            println!("Converted {btc} BTC to {sats} Satoshis");
        }
        Commands::ListWallets => {
            let wallets = wallet.get_wallets().unwrap();
            for (name, pubkey) in wallets {
                println!("Wallet:");
                println!("- Name: {name}");
                println!("- Pubkey: {pubkey}");
            }
        }
        Commands::ImportPartialPrivateKeys {
            identifier,
            private_keys,
            network,
        } => {
            match wallet.import_partial_private_keys(identifier, private_keys.clone(), *network) {
                Ok(_) => println!("Imported partial private keys for {identifier}"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
    }
}
