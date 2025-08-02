use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bitvmx-wallet")]
#[command(about = "A simple Bitcoin wallet CLI", long_about = None)]
pub struct Cli {
    /// Path to the config file (YAML)
    #[arg(short, long, global = true, default_value = "config/regtest.yaml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Fund an address
    SendToAddress {
        to_address: String,
        amount: u64,
        fee_rate: Option<u64>,
    },
    /// Sync the wallet with the Bitcoin node
    SyncWallet,
    /// Cancel a transfer
    CancelTx {
        txid: String,
    },
    /// List unspent outputs
    ListUnspent,
    /// Mine blocks (regtest only)
    Mine { num_blocks: u64 },
    /// Regtest fund the wallet with 150 BTC
    RegtestFundWallet,
    /// Send funds to an address and mine 1 block
    SendToAddressAndMine {
        to_address: String,
        amount: u64,
    },
    /// Convert BTC to SATS
    BtcToSat { btc: f64 },
    /// Get wallet info
    WalletInfo,
}
