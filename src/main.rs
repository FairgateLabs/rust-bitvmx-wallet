mod cli;
pub mod config;
pub mod errors;
pub mod wallet;
pub mod wallet_manager;

use bitcoin::Txid;
use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
use std::process;
use tracing_subscriber::EnvFilter;
use wallet::{RegtestWallet, Wallet};
use wallet_manager::WalletManager;

fn config_trace_aux() {
    let default_modules = ["info", "bitcoincore_rpc=off", "hyper=off", "bollard=off"];

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
        match bitvmx_settings::settings::load_config_file::<Config>(Some(cli.config.clone())) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to load config: {e}");
                process::exit(1);
            }
        };
    config_trace_aux();
    let wallet_manager = match WalletManager::new(config.clone()) {
        Ok(wm) => wm,
        Err(e) => {
            eprintln!("Failed to initialize wallet manager: {e}");
            process::exit(1);
        }
    };

    match &cli.command {
        Commands::SendToAddress {
            identifier,
            to_address,
            amount,
            fee_rate,
        } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => {
                    eprintln!("Error syncing wallet: {e}");
                    process::exit(1);
                }
            }
            match wallet.send_to_address(to_address, *amount, *fee_rate) {
                Ok(tx) => println!("Sent to address, txid: {}", tx.compute_txid()),
                Err(e) => eprintln!(
                    "Error sending to address {to_address} with amount {amount} satoshis: {e}"
                ),
            }
        }
        Commands::SyncWallet { identifier } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => eprintln!("Error syncing wallet: {e}"),
            }
        }
        Commands::CancelTx { identifier, txid } => {
            let txid = match txid.parse::<Txid>() {
                Ok(txid) => txid,
                Err(e) => {
                    eprintln!("Invalid txid: {e}");
                    process::exit(1);
                }
            };
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => {
                    eprintln!("Error syncing wallet: {e}");
                    process::exit(1);
                }
            }
            let wallet_tx = match wallet.get_wallet_tx(txid) {
                Ok(tx) => tx,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            if wallet_tx.is_none() {
                eprintln!("Transaction not found in wallet");
                process::exit(1);
            }
            let wallet_tx = wallet_tx.unwrap();
            match wallet.cancel_tx(&wallet_tx.tx_node.tx) {
                Ok(_) => println!("Transfer reverted"),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::ListUnspent { identifier } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => {
                    eprintln!("Error syncing wallet: {e}");
                    process::exit(1);
                }
            }
            match wallet.list_unspent() {
                Ok(unspent) => {
                    for out in unspent {
                        println!(
                            "OutPoint: {}, Amount: {}, Is Spent: {}",
                            out.outpoint, out.txout.value, out.is_spent
                        );
                    }
                }
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::Mine { num_blocks } => {
            let wallet = match Wallet::from_derive_keypair(
                config.bitcoin.clone(),
                config.wallet.clone(),
                wallet_manager.key_manager.clone(),
                0,
                None,
            ) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Failed to initialize wallet: {e}");
                    process::exit(1);
                }
            };
            match wallet.mine(*num_blocks) {
                Ok(_) => println!("Mined {num_blocks} blocks"),
                Err(e) => eprintln!("Error mining {num_blocks} blocks: {e}"),
            }
        }
        Commands::RegtestFund { identifier } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.fund() {
                Ok(_) => println!("Wallet {identifier} funded with 150 BTC"),
                Err(e) => eprintln!("Error funding wallet: {e}"),
            }
        }
        Commands::SendAndMine {
            identifier,
            to_address,
            amount,
        } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => {
                    eprintln!("Error syncing wallet: {e}");
                    process::exit(1);
                }
            };
            match wallet.fund_address(to_address, *amount) {
                Ok(_) => println!("Funded address {to_address} with amount {amount} satoshis and mined 1 block"),
                Err(e) => eprintln!(
                    "Error funding address {to_address} with amount {amount} satoshis: {e}"
                ),
            }
        }
        Commands::BtcToSat { btc } => {
            let amount = bitcoin::Amount::from_btc(*btc).unwrap();
            let sats = amount.to_sat();
            println!("Converted {btc} BTC to {sats} Satoshis");
        }
        Commands::ListWallets => match wallet_manager.list_wallets() {
            Ok(wallets) => {
                println!("Wallets count: {}", wallets.len());
                for wallet in wallets {
                    println!("Wallet: {} - Pubkey: {}", wallet.0, wallet.1);
                }
            }
            Err(e) => eprintln!("Error listing wallets: {e}"),
        },
        Commands::WalletInfo { identifier } => {
            let mut wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.sync_wallet() {
                Ok(_) => println!("Wallet synced"),
                Err(e) => {
                    eprintln!("Error syncing wallet: {e}");
                    process::exit(1);
                }
            }
            let pubkey = wallet.public_key;
            let address = wallet.receive_address().unwrap();
            let balance = wallet.balance();
            println!("Wallet: {identifier}");
            println!("- Address: {address}");
            println!("- Balance: {balance}");
            println!("- Pubkey: {pubkey}");
        }
        Commands::CreateWallet { identifier } => {
            match wallet_manager.create_new_wallet(identifier) {
                Ok(mut new_wallet) => {
                    println!(
                        "Created new wallet with public_key: {}, start syncing",
                        new_wallet.public_key
                    );
                    match new_wallet.sync_wallet() {
                        Ok(_) => println!("Wallet synced"),
                        Err(e) => {
                            eprintln!("Error syncing wallet: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => eprintln!("Error importing derived keypair: {e}"),
            }
        }
        Commands::ImportDeriveKeypair { identifier, index } => {
            match wallet_manager.create_wallet_from_derive_keypair(identifier, *index) {
                Ok(mut new_wallet) => {
                    println!("Imported derived keypair from index {index}, starting sync");
                    match new_wallet.sync_wallet() {
                        Ok(_) => println!("Wallet synced"),
                        Err(e) => {
                            eprintln!("Error syncing wallet: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => eprintln!("Error importing derived keypair: {e}"),
            }
        }
        Commands::ImportKey {
            identifier,
            private_key,
        } => match wallet_manager.create_wallet_from_private_key(identifier, private_key) {
            Ok(mut new_wallet) => {
                println!("Imported key, starting sync");
                match new_wallet.sync_wallet() {
                    Ok(_) => println!("Wallet synced"),
                    Err(e) => {
                        eprintln!("Error syncing wallet: {e}");
                        process::exit(1);
                    }
                }
            }
            Err(e) => eprintln!("Error importing key: {e}"),
        },
        Commands::ImportPartialPrivateKeys {
            identifier,
            partial_private_keys,
        } => {
            match wallet_manager
                .create_wallet_from_partial_keys(identifier, partial_private_keys.clone())
            {
                Ok(mut new_wallet) => {
                    println!("Imported partial private keys, starting sync");
                    match new_wallet.sync_wallet() {
                        Ok(_) => println!("Wallet synced"),
                        Err(e) => {
                            eprintln!("Error syncing wallet: {e}");
                            process::exit(1);
                        }
                    }
                }
                Err(e) => eprintln!("Error importing partial private keys: {e}"),
            }
        }
        Commands::ExportWallet { identifier } => {
            let wallet = wallet_manager.load_wallet(identifier).unwrap();
            match wallet.export_wallet() {
                Ok((public_key, private_key)) => {
                    println!("Wallet:");
                    println!(" - Pubkey: {public_key}");
                    println!(" - Private key: {private_key}");
                }
                Err(e) => eprintln!("Error exporting wallet: {e}"),
            }
        }
        Commands::ClearWallet { identifier } => match wallet_manager.clear_wallet(identifier) {
            Ok(_) => println!("Cleared wallet"),
            Err(e) => eprintln!("Error clearing wallet: {e}"),
        },
        Commands::ClearAllWallets => match wallet_manager.clear_all_wallets() {
            Ok(_) => println!("Cleared all wallets"),
            Err(e) => eprintln!("Error clearing all wallets: {e}"),
        },
    }
}
