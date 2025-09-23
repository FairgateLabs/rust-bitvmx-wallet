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
    /// Create a new secret key
    CreateWallet { identifier: String },
    /// Import a secret key
    ImportKey {
        identifier: String,
        secret_key: String,
    },
    /// Export a wallet
    ExportWallet { identifier: String },
    /// Add funding
    AddFunding {
        identifier: String,
        funding_id: String,
        outpoint: String,
        amount: u64,
    },
    /// Remove funding
    RemoveFunding {
        identifier: String,
        funding_id: String,
    },
    /// Fund an address
    FundAddress {
        identifier: String,
        funding_id: String,
        to_pubkey: String,
        #[arg(value_delimiter = ',')]
        amount: Vec<u64>,
        fee: u64,
        #[arg(long, default_value = "false")]
        taproot: bool,
        #[arg(long, default_value = "false")]
        confirm: bool,
    },
    /// Confirm a transfer
    ConfirmTransfer {
        identifier: String,
        funding_id: String,
    },
    /// Revert a transfer
    RevertTransfer {
        identifier: String,
        funding_id: String,
    },
    /// List funds
    ListFunds { identifier: String },
    /// Mine blocks (regtest only)
    Mine { num_blocks: u64 },
    /// Regtest fund
    RegtestFund {
        identifier: String,
        funding_id: String,
        amount: u64,
    },
    /// Convert BTC to SATS
    BtcToSat { btc: f64 },
    /// List wallets
    ListWallets,
    /// Import partial private keys to create a wallet from the aggregated private key
    ImportPartialPrivateKeys {
        identifier: String,
        #[arg(value_delimiter = ',')]
        private_keys: Vec<String>,
        network: bitcoin::Network,
    },
}
