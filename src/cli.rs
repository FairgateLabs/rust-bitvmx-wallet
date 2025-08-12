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
    /// Send funds to an address
    SendToAddress {
        identifier: String,
        to_address: String,
        amount: u64,
        fee_rate: Option<u64>,
    },
    /// Sync the wallet with the Bitcoin node
    SyncWallet { identifier: String },
    /// Cancel a transfer
    CancelTx { identifier: String, txid: String },
    /// List unspent outputs
    ListUnspent { identifier: String },
    /// Mine blocks (regtest only)
    Mine { num_blocks: u64 },
    /// Regtest fund the wallet with 150 BTC
    RegtestFund { identifier: String },
    /// Send funds to an address and mine 1 block
    SendAndMine {
        identifier: String,
        to_address: String,
        amount: u64,
    },
    /// Convert BTC to SATS
    BtcToSat { btc: f64 },
    /// List wallets
    ListWallets,
    /// Get wallet info
    WalletInfo { identifier: String },
    /// Create a new secret key
    CreateWallet { identifier: String },
    /// Import a derived keypair
    ImportDeriveKeypair { identifier: String, index: u32 },
    /// Import a secret key
    ImportKey {
        identifier: String,
        private_key: String,
    },
    /// Import partial private keys to create a wallet from the aggregated private key
    ImportPartialPrivateKeys {
        identifier: String,
        #[arg(value_delimiter = ',')]
        partial_private_keys: Vec<String>,
    },
    /// Export a wallet
    ExportWallet { identifier: String },
    /// Clear a wallet
    ClearWallet { identifier: String },
    /// Clear all wallets
    ClearAllWallets,
}
