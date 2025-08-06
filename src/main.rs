
mod cli;
pub mod config;
pub mod errors;
pub mod wallet;

use bitcoin::{Txid};
use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
use std::process;
use tracing_subscriber::EnvFilter;
use wallet::{RegtestWallet, Wallet};

fn config_trace_aux() {
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
    config_trace_aux();

    let mut wallet = match Wallet::new(config.bitcoin, config.wallet) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Failed to initialize wallet: {e}");
            process::exit(1);
        }
    };

    match &cli.command {
        Commands::SendToAddress {
            to_address,
            amount,
            fee_rate,
        } => {
            match wallet.send_to_address(to_address, *amount, *fee_rate) {
                Ok(tx) => println!("Funded address, txid: {}", tx.compute_txid()),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::SyncWallet => match wallet.sync_wallet() {
            Ok(_) => println!("Wallet synced"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::CancelTx {
            txid,
        } =>{
            let txid = match txid.parse::<Txid>() {
                Ok(txid) => txid,
                Err(e) => {
                    eprintln!("Invalid txid: {e}");
                    process::exit(1);
                }
            };
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
        },
        Commands::ListUnspent => match wallet.list_unspent() {
            Ok(unspent) => {
                for out in unspent {
                    println!("OutPoint: {}, Amount: {}, Is Spent: {}",out.outpoint, out.txout.value, out.is_spent);
                }
            }
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::Mine { num_blocks } => match wallet.mine(*num_blocks) {
            Ok(_) => println!("Mined {num_blocks} blocks"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::RegtestFundWallet => match wallet.fund() {
            Ok(_) => println!("Wallet funded with 150 BTC"),
            Err(e) => eprintln!("Error: {e}"),
        },
        Commands::SendToAddressAndMine {
            to_address,
            amount,
        } => {
            match wallet.fund_address(to_address, *amount) {
                Ok(_) => println!("Funded address and mined 1 block"),
                Err(e) => eprintln!("Error: {e}"),
            }
        },
        Commands::BtcToSat { btc } => {
            let amount = bitcoin::Amount::from_btc(*btc).unwrap();
            let sats = amount.to_sat();
            println!("Converted {btc} BTC to {sats} Satoshis");
        }
        Commands::WalletInfo => {
            let pubkey = wallet.public_key.clone();
            let address = wallet.receive_address().unwrap();
            let balance = wallet.balance().unwrap();
            println!("Wallet:");
            println!("- Address: {address}");
            println!("- Balance: {balance}");
            println!("- Pubkey: {pubkey}");
        },
    }
}