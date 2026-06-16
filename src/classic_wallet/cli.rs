use clap::{Parser, Subcommand};
use key_manager::key_type::BitcoinKeyType;

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
    CreateWallet {
        identifier: String,
        #[arg(short = 't', long = "key_type", default_value = "p2wpkh")]
        key_type: BitcoinKeyType,
    },
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
        /// Amount in sats. If omitted, the wallet tries to read the UTXO value from Bitcoin RPC.
        amount: Option<u64>,
    },
    /// Remove funding
    RemoveFunding {
        identifier: String,
        funding_id: String,
    },
    /// Auto-discover wallet UTXOs from mempool.space (mainnet/testnet)
    AutoDiscover { identifier: String },
    /// Join all funds of a wallet into one UTXO
    JoinFunds {
        identifier: String,
        /// Fee per input in sats. Minimum 500. Total fee is this value times the number of funds.
        fee_per_input: u64,
        /// Immediately confirm the local wallet state after sending.
        #[arg(long, default_value = "false")]
        confirm: bool,
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
    /// Start the interactive terminal UI
    #[cfg(feature = "ui")]
    Ui,
    /// Import partial private keys to create a wallet from the aggregated private key
    ImportPartialPrivateKeys {
        identifier: String,
        #[arg(value_delimiter = ',')]
        private_keys: Vec<String>,
        network: bitcoin::Network,
    },
}
