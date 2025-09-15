//! Configuration management for the BitVMX wallet.
//! 
//! This module provides configuration structures for wallet settings, network connections,
//! and key management. It handles loading and validation of configuration from various sources.

use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

/// Configuration for wallet-specific settings.
/// 
/// This struct contains all the configuration parameters needed to initialize
/// and operate a Bitcoin wallet instance.
#[derive(Deserialize, Debug, Clone)]
pub struct WalletConfig {
    /// Path to the SQLite database file for wallet persistence.
    /// 
    /// The database stores wallet state, transaction history, and UTXO information.
    /// If the directory doesn't exist, it will be created automatically.
    pub db_path: String,
    
    /// Optional starting block height for wallet synchronization.
    /// 
    /// If provided, the wallet will start syncing from this block height.
    /// If `None`, the wallet will sync from the genesis block (0).
    pub start_height: Option<u32>,
    
    /// Optional private key in WIF format for receiving addresses.
    /// 
    /// This key is used to generate receiving addresses for the wallet.
    /// If not provided, the wallet will need to be initialized with a key manager.
    pub receive_key: Option<String>,
    
    /// Optional private key in WIF format for change addresses.
    /// 
    /// This key is used to generate change addresses when spending funds.
    /// If not provided, the wallet will be a single descriptor wallet and won't
    /// be able to spend trusted unconfirmed UTXOs.
    pub change_key: Option<String>,
}

impl WalletConfig {
    /// Creates a new `WalletConfig` instance.
    /// 
    /// # Arguments
    /// 
    /// * `db_path` - Path to the SQLite database file
    /// * `start_height` - Optional starting block height for synchronization
    /// * `receive_key` - Optional private key for receiving addresses
    /// * `change_key` - Optional private key for change addresses
    /// 
    /// # Returns
    /// 
    /// A `Result` containing the new `WalletConfig` instance or an error.
    /// 
    /// # Example
/// 
/// ```rust
/// use bitvmx_wallet::config::WalletConfig;
/// 
/// let config = WalletConfig::new(
///     "/path/to/wallet.db".to_string(),
///     Some(800000),
///     Some("L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o".to_string()), // receive key
///     Some("KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8".to_string()), // change key - must be different from receive key
/// )?;
/// ```
    pub fn new(db_path: String, start_height: Option<u32>, receive_key: Option<String>, change_key: Option<String>) -> Result<WalletConfig, anyhow::Error> {
        Ok(WalletConfig {
            db_path,
            start_height,
            receive_key,
            change_key,
        })
    }
}

/// Complete configuration for the BitVMX wallet system.
/// 
/// This struct contains all configuration parameters needed to initialize
/// the entire wallet system, including Bitcoin network settings, key management,
/// storage backends, and wallet-specific settings.
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// Bitcoin network configuration including RPC connection settings.
    /// 
    /// Contains URL, authentication credentials, and network type (mainnet, testnet, regtest).
    pub bitcoin: RpcConfig,
    
    /// Key manager configuration for secure key storage and management.
    /// 
    /// Defines how cryptographic keys are stored, encrypted, and managed.
    pub key_manager: KeyManagerConfig,
    
    /// Configuration for key storage backend.
    /// 
    /// Specifies the storage mechanism for cryptographic keys (file system, database, etc.).
    pub key_storage: StorageConfig,
    
    /// Configuration for general storage backend.
    /// 
    /// Specifies the storage mechanism for wallet data and metadata.
    pub storage: StorageConfig,
    
    /// Wallet-specific configuration settings.
    /// 
    /// Contains database paths, synchronization settings, and key information.
    pub wallet: WalletConfig,
}

impl Config {
    /// Creates a new `Config` instance with all required components.
    /// 
    /// # Arguments
    /// 
    /// * `bitcoin` - Bitcoin network and RPC configuration
    /// * `key_manager` - Key management configuration
    /// * `key_storage` - Key storage backend configuration
    /// * `storage` - General storage backend configuration
    /// * `wallet` - Wallet-specific configuration
    /// 
    /// # Returns
    /// 
    /// A `Result` containing the new `Config` instance or an error.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use bitvmx_wallet::config::{Config, WalletConfig};
    /// use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
    /// use key_manager::config::KeyManagerConfig;
    /// use storage_backend::storage_config::StorageConfig;
    /// 
    /// let config = Config::new(
    ///     RpcConfig::default(),
    ///     KeyManagerConfig::default(),
    ///     StorageConfig::default(),
    ///     StorageConfig::default(),
    ///     WalletConfig::new("/path/to/wallet.db".to_string(), None, None, None)?,
    /// )?;
    /// ```
    pub fn new(
        bitcoin: RpcConfig,
        key_manager: KeyManagerConfig,
        key_storage: StorageConfig,
        storage: StorageConfig,
        wallet: WalletConfig,
    ) -> Result<Config, anyhow::Error> {
        Ok(Config {
            bitcoin,
            key_manager,
            key_storage,
            storage,
            wallet,
        })
    }
}
