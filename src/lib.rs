//! # BitVMX Wallet
//!
//! A comprehensive Bitcoin wallet implementation built with Rust, designed for the BitVMX ecosystem.
//! This crate provides a full-featured wallet with support for multiple key management strategies,
//! transaction handling, and Bitcoin network integration.
//!
//! ## Features
//!
//! - **Multiple Key Management**: Support for private keys, derived keypairs, and partial private keys
//! - **Transaction Operations**: Send, receive, and manage Bitcoin transactions
//! - **Network Integration**: Full integration with Bitcoin Core RPC for blockchain synchronization
//! - **Regtest Support**: Comprehensive testing utilities for development and testing
//! - **CLI Interface**: Command-line interface for wallet operations
//! - **Persistent Storage**: SQLite-based wallet persistence
//!
//! ## Modules
//!
//! - [`wallet`] - Core wallet module containing:
//!   - [`wallet::config`] - Configuration management for wallet and network settings
//!   - [`wallet::errors`] - Error types and handling for wallet operations
//!   - [`wallet::wallet`] - Core wallet functionality and Bitcoin operations
//!   - [`wallet::wallet_manager`] - Multi-wallet management for testing and development
//!   - [`wallet::types`] - Type definitions for destinations and other wallet types
//!   - [`wallet::utils`] - Utility functions for address conversion and descriptor generation
//!   - [`wallet::cli`] - Command-line interface for wallet operations
//! - [`classic_wallet`] - Classic wallet implementation with alternative interface
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bitvmx_wallet::{Wallet, WalletManager, wallet::{config::Config, errors::WalletError}};
//! use key_manager::key_type::BitcoinKeyType;
//!
//! # fn main() -> Result<(), WalletError> {
//! // Load configuration from YAML file
//! let config = protocol_builder::bitvmx_settings::settings::load_config_file::<Config>(Some(
//!     "config/regtest.yaml".to_string()
//! ))?;
//!
//! // Create wallet manager
//! let wallet_manager = WalletManager::new(config)?;
//!
//! // Create a new wallet (single descriptor wallet)
//! let wallet = wallet_manager.create_new_wallet("my_wallet", BitcoinKeyType::P2tr)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Examples
//!
//! See the individual module documentation for detailed examples of each component.
//!
//! ## License
//!
//! This project is licensed under the MIT License.

pub mod wallet;
pub use wallet::types::*;
pub use wallet::wallet::*;
pub use wallet::wallet_manager::*;

pub mod classic_wallet;
pub use classic_wallet::classic_wallet::*;

// re-export bdk_bitcoind_rpc
pub use bdk_bitcoind_rpc;
// re-export bdk_wallet
pub use bdk_wallet;
// re-export protocol_builder and its dependencies
pub use protocol_builder;
pub use protocol_builder::bitcoin;
pub use protocol_builder::bitvmx_bitcoin_rpc;
pub use protocol_builder::bitvmx_settings;
pub use protocol_builder::key_manager;
pub use protocol_builder::storage_backend;
