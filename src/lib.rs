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
//! - [`config`] - Configuration management for wallet and network settings
//! - [`errors`] - Error types and handling for wallet operations
//! - [`wallet`] - Core wallet functionality and Bitcoin operations
//! - [`wallet_manager`] - Multi-wallet management for testing and development
//!
//! ## Quick Start
//!
//! ```rust
//! use bitvmx_wallet::{config::Config, wallet::Wallet, wallet_manager::WalletManager};
//!
//! // Load configuration
//! let config = Config::new(/* ... */)?;
//!
//! // Create wallet manager
//! let wallet_manager = WalletManager::new(config)?;
//!
//! // Create a new wallet (single descriptor wallet)
//! let wallet = wallet_manager.create_new_wallet("my_wallet")?;
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

// re-export bdk_bitcoind_rpc
pub use bdk_bitcoind_rpc;

// re-export bdk_wallet
pub use bdk_wallet;
