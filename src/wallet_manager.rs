//! Multi-wallet management for the BitVMX wallet system.
//!
//! This module provides the `WalletManager` struct for managing multiple wallet instances
//! in a single application. It's only intended to be used for testing and development scenarios
//! where multiple wallets need to be created and managed simultaneously.
//!
//! ## Features
//!
//! - **Multi-wallet Management**: Create, load, and manage multiple wallet instances
//! - **Persistent Storage**: Store wallet metadata in a persistent key-value store
//! - **Key Management Integration**: Integrate with the key manager for secure key handling
//! - **Testing Support**: Utilities for clearing wallets and managing test environments
//!
//! ## Examples
//!
//! ```rust
//! use bitvmx_wallet::wallet_manager::WalletManager;
//! use bitvmx_wallet::config::Config;
//!
//! // Create a wallet manager
//! let wallet_manager = WalletManager::new(config)?;
//!
//! // Create a new wallet
//! let wallet = wallet_manager.create_new_wallet("my_wallet")?;
//!
//! // List all wallets
//! let wallets = wallet_manager.list_wallets()?;
//! for (name, pubkey) in wallets {
//!     println!("Wallet: {} - {}", name, pubkey);
//! }
//! ```

use crate::{
    config::Config,
    errors::WalletError,
    wallet::{RegtestWallet, Wallet},
};
use bitcoin::PublicKey;
use key_manager::{create_key_manager_from_config, key_manager::KeyManager, key_store::KeyStore};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{error, info};

/// Internal storage keys used by the wallet manager.
///
/// This enum defines the different types of keys used for storing wallet metadata
/// in the persistent storage backend.
enum StoreKey {
    /// Key for storing the wallet creation index counter.
    CreateWalletIndex,

    /// Key for storing wallet information by identifier.
    Wallet(String),
}

impl StoreKey {
    /// Generates the storage key string for this key type.
    ///
    /// # Returns
    ///
    /// A string representation of the storage key.
    pub fn get_key(&self) -> String {
        let base = "wallet";
        match self {
            Self::Wallet(identifier) => format!("{base}/name/{identifier}"),
            Self::CreateWalletIndex => format!("{base}/index"),
        }
    }

    /// Generates the database path for this key type.
    ///
    /// # Returns
    ///
    /// A string path to the SQLite database file.
    pub fn db_path(&self) -> String {
        format!("/tmp/wallet_manager/{}.db", self.get_key())
    }
}

/// Manages multiple wallet instances in a single application.
///
/// The `WalletManager` provides functionality to create, load, and manage multiple
/// wallet instances. It's particularly useful for testing and development scenarios
/// where multiple wallets need to be created and managed simultaneously.
///
/// ## Key Features
///
/// - **Multi-wallet Support**: Create and manage multiple wallet instances
/// - **Persistent Metadata**: Store wallet information in a persistent key-value store
/// - **Key Management**: Integrate with the key manager for secure key handling
/// - **Testing Utilities**: Clear wallets and manage test environments
///
/// ## Examples
///
/// ```rust
/// use bitvmx_wallet::wallet_manager::WalletManager;
///
/// // Create a wallet manager
/// let wallet_manager = WalletManager::new(config)?;
///
/// // Create a new wallet (single descriptor wallet)
/// let wallet = wallet_manager.create_new_wallet("alice_wallet")?;
///
/// // Load an existing wallet
/// let wallet = wallet_manager.load_wallet("alice_wallet")?;
///
/// // List all wallets
/// let wallets = wallet_manager.list_wallets()?;
/// for (name, pubkey) in wallets {
///     println!("Wallet: {} - {}", name, pubkey);
/// }
/// ```
pub struct WalletManager {
    /// Configuration for the wallet manager and its components.
    pub config: Config,

    /// Key manager instance for secure key handling.
    pub key_manager: Rc<KeyManager>,

    /// Storage backend for wallet metadata persistence.
    pub store: Rc<Storage>,
}

/// Manage multiple wallets in a single instance, used for testing purposes
impl WalletManager {
    /// Creates a new wallet manager instance.
    ///
    /// This constructor initializes the wallet manager with the provided configuration,
    /// sets up the key manager and storage backend, and prepares the system for
    /// multi-wallet management.
    ///
    /// # Arguments
    ///
    /// * `config` - Complete configuration for the wallet system
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `WalletManager` instance or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet_manager::WalletManager;
    ///
    /// let wallet_manager = WalletManager::new(config)?;
    /// ```
    pub fn new(config: Config) -> Result<WalletManager, WalletError> {
        let storage: Rc<Storage> = Rc::new(Storage::new(&config.storage)?);
        let key_store = KeyStore::new(storage.clone());
        let key_manager = Rc::new(create_key_manager_from_config(
            &config.key_manager,
            key_store,
            storage.clone(),
        )?);
        Ok(Self {
            config,
            key_manager,
            store: storage,
        })
    }

    /// Lists all wallets managed by this wallet manager.
    ///
    /// This method retrieves all wallet identifiers and their associated public keys
    /// from the persistent storage.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of wallet identifiers and their public keys.
    ///
    /// # Example
    ///
    /// ```rust
    /// let wallets = wallet_manager.list_wallets()?;
    /// for (identifier, pubkey) in wallets {
    ///     println!("Wallet: {} - {}", identifier, pubkey);
    /// }
    /// ```
    pub fn list_wallets(&self) -> Result<Vec<(String, PublicKey)>, WalletError> {
        let key = StoreKey::Wallet(String::new()).get_key();
        let mut wallets = Vec::new();

        for identifier_key in self.store.partial_compare_keys(&key)? {
            let identifier = identifier_key.strip_prefix(&key).unwrap().to_string();
            let pubkey: PublicKey = self
                .store
                .get(&identifier_key)?
                .ok_or(WalletError::KeyNotFound(identifier_key))?;

            wallets.push((identifier, pubkey));
        }

        Ok(wallets)
    }

    /// Creates a new wallet with an automatically derived key pair.
    ///
    /// This method creates a new wallet using a key pair derived from the key manager
    /// with an automatically incremented index. The wallet is stored with the given identifier.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**: This method creates a single descriptor wallet without a change descriptor.
    /// This means the wallet won't be able to spend trusted unconfirmed UTXOs, which can limit
    /// its functionality for certain use cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// let wallet = wallet_manager.create_new_wallet("alice_wallet")?;
    /// println!("Created wallet with public key: {}", wallet.public_key);
    /// ```
    pub fn create_new_wallet(&self, identifier: &str) -> Result<Wallet, WalletError> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let index = self.get_wallet_index()?;
        let wallet = Wallet::from_derive_keypair(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            index,
            None,
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    /// Creates a wallet using a derived key pair from a specific index.
    ///
    /// This method creates a new wallet using a key pair derived from the key manager
    /// at the specified index. The wallet is stored with the given identifier.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `index` - Derivation index for the key pair
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**: This method creates a single descriptor wallet without a change descriptor.
    /// This means the wallet won't be able to spend trusted unconfirmed UTXOs, which can limit
    /// its functionality for certain use cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// let wallet = wallet_manager.create_wallet_from_derive_keypair("bob_wallet", 42)?;
    /// println!("Created wallet with public key: {}", wallet.public_key);
    /// ```
    pub fn create_wallet_from_derive_keypair(
        &self,
        identifier: &str,
        index: u32,
    ) -> Result<Wallet, WalletError> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_derive_keypair(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            index,
            None,
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    /// Creates a wallet from a private key.
    ///
    /// This method creates a new wallet using the provided private key. The private key
    /// is imported into the key manager and the wallet is stored with the given identifier.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `private_key` - Private key in WIF (Wallet Import Format)
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**: This method creates a single descriptor wallet without a change descriptor.
    /// This means the wallet won't be able to spend trusted unconfirmed UTXOs, which can limit
    /// its functionality for certain use cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// let wallet = wallet_manager.create_wallet_from_private_key(
    ///     "charlie_wallet",
    ///     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o"
    /// )?;
    /// println!("Created wallet with public key: {}", wallet.public_key);
    /// ```
    pub fn create_wallet_from_private_key(
        &self,
        identifier: &str,
        private_key: &str,
    ) -> Result<Wallet, WalletError> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_private_key(
            self.config.bitcoin.clone(),
            config_wallet,
            private_key,
            None,
        )?;

        let public_key = self.key_manager.import_private_key(private_key)?;
        self.store.set(key, public_key, None)?;

        Ok(wallet)
    }

    /// Creates a wallet from partial private keys for MuSig2 multi-signature.
    ///
    /// This method creates a new wallet using partial private keys that are combined
    /// to form a complete private key for MuSig2 multi-signature operations.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier for the new wallet
    /// * `partial_keys` - Vector of partial private keys (hex or WIF format)
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**: This method creates a single descriptor wallet without a change descriptor.
    /// This means the wallet won't be able to spend trusted unconfirmed UTXOs, which can limit
    /// its functionality for certain use cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// let partial_keys = vec![
    ///     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
    ///     "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
    /// ];
    ///
    /// let wallet = wallet_manager.create_wallet_from_partial_keys(
    ///     "multisig_wallet",
    ///     partial_keys
    /// )?;
    /// println!("Created multisig wallet with public key: {}", wallet.public_key);
    /// ```
    pub fn create_wallet_from_partial_keys(
        &self,
        identifier: &str,
        partial_keys: Vec<String>,
    ) -> Result<Wallet, WalletError> {
        if partial_keys.is_empty() {
            error!("No partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys);
        }

        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_partial_keys(
            self.config.bitcoin.clone(),
            config_wallet,
            partial_keys,
            self.key_manager.clone(),
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    /// Loads an existing wallet by its identifier.
    ///
    /// This method retrieves a wallet's public key from storage and creates a wallet
    /// instance using the key manager.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier of the wallet to load
    ///
    /// # Returns
    ///
    /// A `Result` containing the loaded `Wallet` instance or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let wallet = wallet_manager.load_wallet("alice_wallet")?;
    /// println!("Loaded wallet: {}", wallet.name);
    /// ```
    pub fn load_wallet(&self, identifier: &str) -> Result<Wallet, WalletError> {
        if identifier.trim().is_empty() {
            return Err(WalletError::KeyNotFound(format!(
                "Invalid identifier: {identifier}"
            )));
        }
        let key = StoreKey::Wallet(identifier.to_string()).get_key();
        info!("Loading wallet {identifier} with key {key}");
        let pub_key: PublicKey = self.store.get(&key)?.unwrap();

        Wallet::from_key_manager(
            self.config.bitcoin.clone(),
            self.config.wallet.clone(),
            self.key_manager.clone(),
            &pub_key,
            None,
        )
    }

    /// Clears a specific wallet's database.
    ///
    /// This method removes the wallet's database file, effectively clearing all
    /// wallet state and transaction history.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Unique identifier of the wallet to clear
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// wallet_manager.clear_wallet("test_wallet")?;
    /// println!("Cleared test wallet");
    /// ```
    pub fn clear_wallet(&self, identifier: &str) -> Result<(), WalletError> {
        if identifier.trim().is_empty() {
            return Err(WalletError::KeyNotFound(format!(
                "Invalid identifier: {identifier}"
            )));
        }

        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if !self.store.has_key(&key)? {
            return Err(WalletError::KeyNotFound(key));
        }
        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();
        info!("Clearing db at {}", config_wallet.db_path);
        Wallet::clear_db(&config_wallet)?;
        Ok(())
    }

    /// Clears all wallets managed by this wallet manager.
    ///
    /// This method removes the database files for all wallets, effectively clearing
    /// all wallet state and transaction history.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// wallet_manager.clear_all_wallets()?;
    /// println!("Cleared all wallets");
    /// ```
    pub fn clear_all_wallets(&self) -> Result<(), WalletError> {
        let key = StoreKey::Wallet(String::new()).get_key();
        info!("key with all wallets {key}");
        for identifier_key in self.store.partial_compare_keys(&key)? {
            let identifier = identifier_key.strip_prefix(&key).unwrap().to_string();
            self.clear_wallet(&identifier)?;
        }
        Ok(())
    }

    /// Gets the next available wallet index and increments the counter.
    ///
    /// This method retrieves the current wallet creation index from storage,
    /// increments it, and returns the current value for use in wallet creation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the next wallet index or an error.
    fn get_wallet_index(&self) -> Result<u32, WalletError> {
        let key_index = StoreKey::CreateWalletIndex.get_key();
        let index = self.store.get(&key_index)?.unwrap_or(0);
        // Increment the index to save for next wallet
        self.store.set(key_index, index + 1, None)?;
        Ok(index)
    }
}
