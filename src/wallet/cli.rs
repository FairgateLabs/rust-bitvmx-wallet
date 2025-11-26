//! Command-line interface for the BitVMX wallet.
//!
//! This module provides the command-line interface for interacting with the BitVMX wallet.
//! It uses the `clap` crate to define and parse command-line arguments and subcommands.
//!
//! ## Features
//!
//! - **Transaction Operations**: Send funds, sync wallets, and manage transactions
//! - **Wallet Management**: Create, import, export, and clear wallets
//! - **Testing Utilities**: Regtest-specific commands for development and testing
//! - **Blockchain Operations**: Mine blocks and manage blockchain state
//! - **Utility Functions**: Convert between BTC and satoshis
//!
//! ## Examples
//!
//! ```bash
//! # Create a new wallet
//! bitvmx-wallet create-wallet my_wallet
//!
//! # Send funds to an address
//! bitvmx-wallet send-to-address my_wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 100000
//!
//! # Sync a wallet
//! bitvmx-wallet sync-wallet my_wallet
//!
//! # List all wallets
//! bitvmx-wallet list-wallets
//! ```

use clap::{Parser, Subcommand};
use key_manager::key_type::BitcoinKeyType;

/// Main command-line interface for the BitVMX wallet.
///
/// This struct defines the top-level CLI structure with global options and subcommands.
/// It uses the `clap` crate for argument parsing and help generation.
///
/// ## Global Options
///
/// - `--config` / `-c`: Path to the configuration file (default: "config/regtest.yaml")
///
/// ## Subcommands
///
/// The CLI provides various subcommands for different wallet operations:
/// - Transaction operations (send, sync, cancel)
/// - Wallet management (create, import, export, clear)
/// - Testing utilities (mine, fund)
/// - Utility functions (convert BTC to satoshis)
#[derive(Parser)]
#[command(name = "bitvmx-wallet")]
#[command(about = "A simple Bitcoin wallet CLI", long_about = None)]
pub struct Cli {
    /// Path to the config file (YAML)
    ///
    /// Specifies the configuration file to use for wallet operations.
    /// The file should contain Bitcoin network settings, key management configuration,
    /// and wallet-specific settings.
    #[arg(short, long, global = true, default_value = "config/regtest.yaml")]
    pub config: String,

    /// The subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for the BitVMX wallet CLI.
///
/// This enum defines all the available subcommands that can be executed
/// through the command-line interface.
#[derive(Subcommand)]
pub enum Commands {
    /// Send funds to a Bitcoin address.
    ///
    /// Creates and broadcasts a transaction to send the specified amount
    /// to the given Bitcoin address.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    /// * `to_address` - Destination Bitcoin address
    /// * `amount` - Amount to send in satoshis
    /// * `fee_rate` - Optional fee rate in satoshis per virtual byte
    SendToAddress {
        /// Wallet identifier
        identifier: String,
        /// Destination Bitcoin address
        to_address: String,
        /// Amount to send in satoshis
        amount: u64,
        /// Optional fee rate in satoshis per virtual byte
        fee_rate: Option<u64>,
    },

    /// Synchronize a wallet with the Bitcoin network.
    ///
    /// Downloads and processes all blocks and mempool transactions
    /// to update the wallet's state to the latest blockchain state.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    SyncWallet {
        /// Wallet identifier
        identifier: String,
    },

    /// Cancel a pending transaction.
    ///
    /// Removes a transaction from the wallet's pending transaction list.
    /// This is useful for transactions that haven't been confirmed yet.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    /// * `txid` - Transaction ID to cancel
    CancelTx {
        /// Wallet identifier
        identifier: String,
        /// Transaction ID to cancel
        txid: String,
    },

    /// List all unspent transaction outputs (UTXOs).
    ///
    /// Displays all unspent outputs in the wallet that can be used
    /// for creating new transactions.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    ListUnspent {
        /// Wallet identifier
        identifier: String,
    },

    /// Mine blocks (regtest only).
    ///
    /// Generates the specified number of blocks and sends coinbase rewards
    /// to a default address. This command is only available in regtest mode.
    ///
    /// # Arguments
    ///
    /// * `num_blocks` - Number of blocks to mine
    /// * `key_type` - Bitcoin key type for the mining address
    Mine {
        /// Number of blocks to mine
        num_blocks: u64,
        /// Bitcoin key type for the mining address
        #[arg(short = 't', long = "key_type", default_value = "p2pkh")]
        key_type: BitcoinKeyType,
    },

    /// Fund a wallet with 150 BTC (regtest only).
    ///
    /// Mines blocks and sends coinbase rewards to the specified wallet,
    /// giving it 150 BTC for testing purposes. This command is only available in regtest mode.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier to fund
    RegtestFund {
        /// Wallet identifier to fund
        identifier: String,
    },

    /// Send funds to an address and mine 1 block (regtest only).
    ///
    /// Sends the specified amount to the given address and then mines
    /// one block to confirm the transaction. This command is only available in regtest mode.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    /// * `to_address` - Destination Bitcoin address
    /// * `amount` - Amount to send in satoshis
    SendAndMine {
        /// Wallet identifier
        identifier: String,
        /// Destination Bitcoin address
        to_address: String,
        /// Amount to send in satoshis
        amount: u64,
    },

    /// Convert BTC to satoshis.
    ///
    /// Utility command to convert a Bitcoin amount to its equivalent in satoshis.
    ///
    /// # Arguments
    ///
    /// * `btc` - Amount in Bitcoin (e.g., 0.001)
    BtcToSat {
        /// Amount in Bitcoin
        btc: f64,
    },

    /// List all managed wallets.
    ///
    /// Displays all wallets that are managed by the wallet manager,
    /// showing their identifiers and associated public keys.
    ListWallets,

    /// Get detailed information about a wallet.
    ///
    /// Displays comprehensive information about a specific wallet,
    /// including its address, balance, and public key.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    WalletInfo {
        /// Wallet identifier
        identifier: String,
    },

    /// Create a new wallet with an automatically derived key pair.
    ///
    /// Creates a new wallet using a key pair derived from the key manager
    /// with an automatically incremented index.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `key_type` - Bitcoin key type (p2pkh, p2wpkh, p2tr, etc.)
    CreateWallet {
        /// Unique identifier for the new wallet
        identifier: String,
        /// Bitcoin key type
        #[arg(short = 't', long = "key_type", default_value = "p2pkh")]
        key_type: BitcoinKeyType,
    },

    /// Import a derived key pair from a specific index.
    ///
    /// Creates a wallet using a key pair derived from the key manager
    /// at the specified index.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `index` - Derivation index for the key pair
    /// * `key_type` - Bitcoin key type (p2pkh, p2wpkh, p2tr, etc.)
    ImportDeriveKeypair {
        /// Unique identifier for the new wallet
        identifier: String,
        /// Derivation index for the key pair
        index: u32,
        /// Bitcoin key type
        #[arg(short = 't', long = "key_type", default_value = "p2pkh")]
        key_type: BitcoinKeyType,
    },

    /// Import a private key to create a wallet.
    ///
    /// Creates a wallet using the provided private key in WIF format.
    /// The private key is imported into the key manager.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `private_key` - Private key in WIF (Wallet Import Format)
    ImportKey {
        /// Unique identifier for the new wallet
        identifier: String,
        /// Private key in WIF format
        private_key: String,
    },

    /// Import partial private keys to create a MuSig2 wallet.
    ///
    /// Creates a wallet using partial private keys that are combined
    /// to form a complete private key for MuSig2 multi-signature operations.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `partial_private_keys` - Comma-separated list of partial private keys
    ImportPartialPrivateKeys {
        /// Unique identifier for the new wallet
        identifier: String,
        /// Comma-separated list of partial private keys
        #[arg(value_delimiter = ',')]
        partial_private_keys: Vec<String>,
    },

    /// Export wallet information.
    ///
    /// Exports the wallet's public and private key descriptors.
    /// This is useful for backup purposes or wallet migration.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier
    ExportWallet {
        /// Wallet identifier
        identifier: String,
    },

    /// Clear a specific wallet's database.
    ///
    /// Removes the wallet's database file, effectively clearing all
    /// wallet state and transaction history.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Wallet identifier to clear
    ClearWallet {
        /// Wallet identifier to clear
        identifier: String,
    },

    /// Clear all managed wallets.
    ///
    /// Removes the database files for all wallets, effectively clearing
    /// all wallet state and transaction history.
    ClearAllWallets,
}
