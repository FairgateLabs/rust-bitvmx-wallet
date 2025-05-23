use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bitvmx-wallet")]
#[command(about = "A simple Bitcoin wallet CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new secret key
    CreateKey { identifier: String, index: u32 },
    /// Import a secret key
    ImportKey {
        identifier: String,
        secret_key: String,
    },
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
        amount: u64,
        fee: u64,
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
}
