//! Core wallet functionality for the BitVMX wallet.
//!
//! This module provides the main `Wallet` struct and related functionality for
//! Bitcoin wallet operations, including transaction management, blockchain
//! synchronization, and key management.
//!
//! ## Features
//!
//! - **Transaction Operations**: Send and receive Bitcoin transactions
//! - **Blockchain Synchronization**: Sync with Bitcoin nodes for latest state
//! - **Key Management**: Support for various key types and derivation methods
//! - **Address Generation**: Generate receiving and change addresses
//! - **Regtest Support**: Testing utilities for development environments
//!
//! ## Examples
//!
//! ```rust
//! use bitvmx_wallet::{wallet::Wallet, config::WalletConfig};
//! use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
//! use bitcoin::PublicKey;
//!
//! // Create a wallet from a private key with change descriptor
//! // Change descriptors allow the wallet to use trusted unconfirmed UTXOs
//! let wallet = Wallet::from_private_key(
//!     rpc_config,
//!     wallet_config,
//!     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o", // receive key
//!     Some("KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8"), // change key - must be different from receive key
//! )?;
//!
//! // Sync the wallet
//! wallet.sync_wallet()?;
//!
//! // Send a transaction
//! let tx = wallet.send_to_address(
//!     "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
//!     100000, // 0.001 BTC
//!     Some(5), // 5 sat/vB fee rate
//! )?;
//! ```

use crate::wallet::types::{Destination, Emission};
use crate::wallet::utils::{
    p2tr_descriptor, p2wpkh_descriptor, pub_key_to_p2tr, pub_key_to_p2wpkh,
};
use crate::wallet::{config::WalletConfig, errors::WalletError};
use bitcoin::{
    key::Secp256k1, Address, Amount, Block, FeeRate, Network, PrivateKey, Psbt, PublicKey,
    Transaction, Txid,
};

use bitvmx_bitcoin_rpc::{reqwest_https::ReqwestHttpsTransport, rpc_config::RpcConfig};
use key_manager::key_manager::KeyManager;
use tracing::{debug, error, info, trace};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{jsonrpc, Client, RpcApi},
    BlockEvent, Emitter, MempoolEvent,
};
use bdk_wallet::{
    coin_selection::DefaultCoinSelectionAlgorithm, rusqlite::Connection,
    wallet_name_from_descriptor, Balance, KeychainKind, LocalOutput, PersistedWallet, SignOptions,
    TxBuilder, TxOrdering, Wallet as BdkWallet, WalletTx,
};
use ctrlc;
use std::{
    fmt::{self, Display},
    fs,
    path::Path,
    rc::Rc,
    str::FromStr,
    sync::{mpsc::channel, Arc},
    thread::spawn,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// A Bitcoin wallet instance with full functionality.
///
/// The `Wallet` struct provides comprehensive Bitcoin wallet functionality,
/// including transaction creation, blockchain synchronization, address generation,
/// and key management. It wraps the BDK wallet library and provides additional
/// features specific to the BitVMX ecosystem.
///
/// ## Key Features
///
/// - **Multiple Key Types**: Support for private keys, derived keypairs, and partial private keys
/// - **Transaction Management**: Create, sign, and broadcast Bitcoin transactions
/// - **Blockchain Sync**: Synchronize with Bitcoin nodes for latest blockchain state
/// - **Address Generation**: Generate receiving and change addresses
/// - **Persistent Storage**: SQLite-based wallet state persistence
/// - **Regtest Support**: Testing utilities for development environments
///
/// ## Examples
///
/// ```rust
/// use bitvmx_wallet::wallet::Wallet;
///
/// // Create a wallet from a private key with change descriptor
/// // Change descriptors allow the wallet to use trusted unconfirmed UTXOs
/// let mut wallet = Wallet::from_private_key(
///     rpc_config,
///     wallet_config,
///     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o", // receive key
///     Some("KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8"), // change key - must be different from receive key
/// )?;
///
/// // Sync with the blockchain
/// wallet.sync_wallet()?;
///
/// // Get wallet balance
/// let balance = wallet.balance();
/// println!("Balance: {} sats", balance.confirmed);
///
/// // Generate a receiving address
/// let address = wallet.receive_address()?;
/// println!("Receive address: {}", address);
///
/// // Send a transaction
/// let tx = wallet.send_to_address(
///     "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
///     100000, // 0.001 BTC
///     Some(5), // 5 sat/vB fee rate
/// )?;
/// println!("Transaction sent: {}", tx.compute_txid());
/// ```
pub struct Wallet {
    /// The Bitcoin network this wallet operates on (mainnet, testnet, or regtest).
    pub network: bitcoin::Network,

    /// RPC client for communicating with the Bitcoin Core node.
    pub rpc_client: Arc<Client>,

    /// The underlying BDK wallet instance.
    pub bdk_wallet: PersistedWallet<Connection>,

    /// The public key associated with this wallet.
    pub public_key: PublicKey,

    /// The name/identifier of this wallet.
    pub name: String,

    /// The starting block height for wallet synchronization.
    pub start_height: u32,

    /// Whether the wallet has completed initial synchronization.
    pub is_ready: bool,

    /// SQLite database connection for wallet persistence.
    conn: Connection,
}

impl Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Wallet {
    /// Creates a wallet from a public key by retrieving the private key from the key manager.
    ///
    /// This constructor is useful when you have a public key and want to create a wallet
    /// using the corresponding private key stored in the key manager.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet-specific configuration settings
    /// * `key_manager` - Key manager instance for key retrieval
    /// * `public_key` - The public key to use for wallet creation
    /// * `change_public_key` - Optional public key for change addresses
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// If no change public key is provided, the wallet will be a single descriptor wallet
    /// and won't be able to spend trusted unconfirmed UTXOs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    /// use bitcoin::PublicKey;
    ///
    /// let wallet = Wallet::from_key_manager(
    ///     bitcoin_config,
    ///     wallet_config,
    ///     key_manager,
    ///     &public_key,
    ///     Some(&change_public_key),
    /// )?;
    /// ```
    pub fn from_key_manager(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        public_key: &PublicKey,
        change_public_key: Option<&PublicKey>,
    ) -> Result<Wallet, WalletError> {
        let descriptor = p2wpkh_descriptor(&key_manager.export_secret(public_key)?.to_wif())?;
        let change_descriptor = match change_public_key {
            Some(change_public_key) => Some(p2wpkh_descriptor(
                &key_manager.export_secret(change_public_key)?.to_wif(),
            )?),
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Creates a wallet by deriving a key pair from the key manager using an index.
    ///
    /// This constructor derives a new key pair from the key manager's master key
    /// using the specified index, then creates a wallet with that key pair.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet-specific configuration settings
    /// * `key_manager` - Key manager instance for key derivation
    /// * `index` - The derivation index for the key pair
    /// * `change_index` - Optional derivation index for change addresses
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**:
    /// - If no change index is provided, the wallet will be a single descriptor wallet
    ///   and won't be able to spend trusted unconfirmed UTXOs. This means you cannot use unconfirmed
    ///   transactions as inputs for new transactions, which can limit the wallet's functionality.
    /// - The change index must be different from the main key index to avoid address reuse
    ///   and maintain proper wallet security.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    ///
    /// // Create wallet with change descriptor (recommended)
    /// // This allows using trusted unconfirmed UTXOs
    /// let wallet = Wallet::from_derive_keypair(
    ///     bitcoin_config,
    ///     wallet_config,
    ///     key_manager,
    ///     0, // Use index 0 for the main key
    ///     Some(1), // Use index 1 for change addresses (must be different from main key)
    /// )?;
    /// ```
    pub fn from_derive_keypair(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        index: u32,
        change_index: Option<u32>,
    ) -> Result<Wallet, WalletError> {
        let public_key = key_manager.derive_keypair(index)?;
        let descriptor = p2wpkh_descriptor(&key_manager.export_secret(&public_key)?.to_wif())?;
        let change_descriptor = match change_index {
            Some(change_index) => {
                let change_public_key = key_manager.derive_keypair(change_index)?;
                Some(p2wpkh_descriptor(
                    &key_manager.export_secret(&change_public_key)?.to_wif(),
                )?)
            }
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            &public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Creates a wallet from a private key and stores it in the key manager.
    ///
    /// This constructor creates a wallet using a provided private key in WIF format.
    /// The private key is stored in the key manager for future use.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet-specific configuration settings
    /// * `private_key` - Private key in WIF (Wallet Import Format)
    /// * `change_private_key` - Optional private key for change addresses
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// **Important**:
    /// - If no change private key is provided, the wallet will be a single descriptor wallet
    ///   and won't be able to spend trusted unconfirmed UTXOs. This means you cannot use unconfirmed
    ///   transactions as inputs for new transactions, which can limit the wallet's functionality.
    /// - The change private key must be different from the receive private key to avoid address reuse
    ///   and maintain proper wallet security.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    ///
    /// // Create wallet with change descriptor (recommended)
    /// // This allows using trusted unconfirmed UTXOs
    /// let wallet = Wallet::from_private_key(
    ///     bitcoin_config,
    ///     wallet_config,
    ///     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o", // receive key
    ///     Some("KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8"), // change key - must be different from receive key
    /// )?;
    /// ```
    pub fn from_private_key(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        private_key: &str,
        change_private_key: Option<&str>,
    ) -> Result<Wallet, WalletError> {
        let public_key = PrivateKey::from_str(private_key)?.public_key(&Secp256k1::new());
        let descriptor = p2wpkh_descriptor(private_key)?;
        let change_descriptor = match change_private_key {
            Some(change_private_key) => Some(p2wpkh_descriptor(change_private_key)?),
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            &public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Creates a wallet from configuration file settings.
    ///
    /// This constructor creates a wallet using keys specified in the wallet configuration.
    /// The receive key is required, while the change key is optional.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet configuration containing key information
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// - Keys must be in WIF (Wallet Import Format)
    /// - The receive key is required in the configuration
    /// - **Important**:
    ///   - If no change key is provided, the wallet will be a single descriptor wallet
    ///     and won't be able to spend trusted unconfirmed UTXOs. This means you cannot use unconfirmed
    ///     transactions as inputs for new transactions, which can limit the wallet's functionality.
    ///   - The change key must be different from the receive key to avoid address reuse
    ///     and maintain proper wallet security.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    ///
    /// // Create wallet with change descriptor (recommended)
    /// // This allows using trusted unconfirmed UTXOs
    /// let wallet = Wallet::from_config(
    ///     bitcoin_config,
    ///     wallet_config, // Contains receive_key and optional change_key (must be different)
    /// )?;
    /// ```
    pub fn from_config(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
    ) -> Result<Wallet, WalletError> {
        let receive_key = match wallet_config.receive_key.clone() {
            Some(receive_key) => receive_key,
            None => {
                return Err(WalletError::InvalidReceiveKey(
                    "No receive key provided in config file".to_string(),
                ))
            }
        };
        let change_key = wallet_config.change_key.clone();
        Self::from_private_key(
            bitcoin_config,
            wallet_config,
            &receive_key,
            change_key.as_deref(),
        )
    }

    /// Creates a wallet from partial private keys for MuSig2 multi-signature.
    ///
    /// This constructor creates a wallet using partial private keys that are combined
    /// to form a complete private key for MuSig2 multi-signature operations.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet-specific configuration settings
    /// * `partial_private_keys` - Vector of partial private keys (hex or WIF format)
    /// * `key_manager` - Key manager instance for key aggregation
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// - Partial keys can be provided in hex format (64 characters) or WIF format (52 characters)
    /// - All keys must be in the same format
    /// - The keys are aggregated to form a complete private key
    /// - The resulting wallet uses P2TR (Pay-to-Taproot) addresses
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    ///
    /// let partial_keys = vec![
    ///     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
    ///     "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
    /// ];
    ///
    /// let wallet = Wallet::from_partial_keys(
    ///     bitcoin_config,
    ///     wallet_config,
    ///     partial_keys,
    ///     key_manager,
    /// )?;
    /// ```
    pub fn from_partial_keys(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        partial_private_keys: Vec<String>,
        key_manager: Rc<KeyManager>,
    ) -> Result<Wallet, WalletError> {
        if partial_private_keys.is_empty() {
            error!("No partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys);
        }
        let aggregated_public_key = if partial_private_keys.iter().all(|key| key.len() == 64) {
            key_manager.import_partial_secret_keys(partial_private_keys, bitcoin_config.network)?
        } else if partial_private_keys.iter().all(|key| key.len() == 52) {
            key_manager.import_partial_private_keys(partial_private_keys, bitcoin_config.network)?
        } else {
            error!("Invalid partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys);
        };

        let descriptor =
            p2tr_descriptor(&key_manager.export_secret(&aggregated_public_key)?.to_wif())?;
        Self::new(
            bitcoin_config,
            wallet_config,
            &aggregated_public_key,
            &descriptor,
            None,
        )
    }

    /// Creates a new wallet instance with initial data persisted to a SQLite database.
    ///
    /// This is the main constructor that initializes a wallet with the provided
    /// configuration and descriptors. The wallet data is persisted to a SQLite database
    /// for state management and recovery.
    ///
    /// # Arguments
    ///
    /// * `bitcoin_config` - Bitcoin network and RPC configuration
    /// * `wallet_config` - Wallet-specific configuration settings
    /// * `public_key` - The public key associated with this wallet
    /// * `descriptor` - Bitcoin output descriptor for receiving addresses
    /// * `change_descriptor` - Optional descriptor for change addresses
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Wallet` instance or an error.
    ///
    /// # Notes
    ///
    /// - Descriptor secret keys are not persisted to the database for security
    /// - **Important**:
    ///   - If no change descriptor is provided, the wallet will be a single descriptor wallet
    ///     and won't be able to spend trusted unconfirmed UTXOs. This means you cannot use unconfirmed
    ///     transactions as inputs for new transactions, which can limit the wallet's functionality.
    ///   - The change descriptor must be different from the receive descriptor to avoid address reuse
    ///     and maintain proper wallet security.
    /// - The database directory is created automatically if it doesn't exist
    ///
    /// # Example
    ///
    /// ```rust
    /// use bitvmx_wallet::wallet::Wallet;
    /// use bitcoin::PublicKey;
    ///
    /// // Create wallet with change descriptor (recommended)
    /// // This allows using trusted unconfirmed UTXOs
    /// let wallet = Wallet::new(
    ///     bitcoin_config,
    ///     wallet_config,
    ///     &public_key,
    ///     "wpkh(L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o)", // receive descriptor
    ///     Some("wpkh(KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8)"), // change descriptor - must be different from receive
    /// )?;
    /// ```
    pub fn new(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        public_key: &PublicKey,
        descriptor: &str,
        change_descriptor: Option<&str>,
    ) -> Result<Wallet, WalletError> {
        // Create a Bitcoin RPC client
        let transport = if bitcoin_config.username != "" {
            ReqwestHttpsTransport::builder()
                .url(&bitcoin_config.url.clone())
                .map_err(|e| WalletError::URLError(bitcoin_config.url, e.to_string()))?
                .basic_auth(
                    bitcoin_config.username.to_owned(),
                    Some(bitcoin_config.password.clone()),
                )
                .build()
        } else {
            ReqwestHttpsTransport::builder()
                .url(&bitcoin_config.url)
                .map_err(|e| WalletError::URLError(bitcoin_config.url, e.to_string()))?
                .build()
        };

        let from_jsonrpc = jsonrpc::client::Client::with_transport(transport);
        let rpc_client = Arc::new(Client::from_jsonrpc(from_jsonrpc));

        let start_height = wallet_config.start_height.unwrap_or(0);
        // Wallet config
        let db_path = wallet_config.db_path.clone();
        // Ensure the directory exists
        Self::ensure_db_directory(&db_path)?;
        // Open or create a new sqlite database.
        let mut conn = Connection::open(db_path)?;

        // Get or create a wallet with initial data read from rusqlite database.
        let bdk_wallet = Self::init_bdk_wallet(
            &mut conn,
            bitcoin_config.network,
            descriptor,
            change_descriptor,
        )?;

        let name = wallet_name_from_descriptor(
            descriptor,
            change_descriptor,
            bitcoin_config.network,
            bdk_wallet.secp_ctx(),
        )?;

        Ok(Self {
            network: bitcoin_config.network,
            rpc_client,
            bdk_wallet,
            name,
            public_key: *public_key,
            start_height,
            is_ready: false,
            conn,
        })
    }

    /// Load or create a wallet with initial data and persist it to the rusqlite database.
    /// Note that the descriptor secret keys are not persisted to the database.
    fn init_bdk_wallet(
        conn: &mut Connection,
        network: Network,
        descriptor: &str,
        change_descriptor: Option<&str>,
    ) -> Result<PersistedWallet<Connection>, WalletError> {
        // Load the wallet from the database
        let mut load_params =
            BdkWallet::load().descriptor(KeychainKind::External, Some(descriptor.to_string()));
        if let Some(chd) = change_descriptor {
            load_params = load_params.descriptor(KeychainKind::Internal, Some(chd.to_string()));
        }
        let wallet_opt = load_params
            .check_network(network)
            .extract_keys()
            .load_wallet(conn)
            .map_err(|e| WalletError::LoadWalletWithPersistError(Box::new(e)))?;

        let mut wallet = match wallet_opt {
            Some(_wallet) => _wallet,
            // If the wallet is not found, create a new one
            None => match change_descriptor {
                Some(change) => BdkWallet::create(descriptor.to_string(), change.to_string())
                    .network(network)
                    .create_wallet(conn)
                    .map_err(|e| WalletError::CreateWalletError(Box::new(e)))?,
                // If no change descriptor is provided, create a single descriptor wallet
                // see https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.create_single
                None => BdkWallet::create_single(descriptor.to_string())
                    .network(network)
                    .create_wallet(conn)
                    .map_err(|e| WalletError::CreateWalletError(Box::new(e)))?,
            },
        };

        // Persist the wallet to the database
        wallet.persist(conn)?;
        Ok(wallet)
    }

    /// Returns the current wallet balance.
    ///
    /// This method returns the wallet's balance information including confirmed,
    /// unconfirmed, and immature balances.
    ///
    /// # Returns
    ///
    /// A `Balance` struct containing the wallet's balance information.
    ///
    /// # Example
    ///
    /// ```rust
    /// let balance = wallet.balance();
    /// println!("Confirmed: {} sats", balance.confirmed);
    /// println!("Unconfirmed: {} sats", balance.unconfirmed);
    /// println!("Immature: {} sats", balance.immature);
    /// ```
    pub fn balance(&self) -> Balance {
        self.bdk_wallet.balance()
    }

    /// Generates a new receiving address for the wallet.
    ///
    /// This method generates the next unused receiving address from the wallet's
    /// external keychain. The address is marked as used and the wallet state is persisted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new receiving address or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let address = wallet.receive_address()?;
    /// println!("New receiving address: {}", address);
    /// ```
    pub fn receive_address(&mut self) -> Result<Address, WalletError> {
        let address_info = self.bdk_wallet.reveal_next_address(KeychainKind::External);
        // Mark previous address as used for receiving and persist to sqlite database.
        self.persist_wallet()?;
        Ok(address_info.address)
    }

    /// Creates and signs a transaction to send funds to a specific addresses.
    ///
    /// This method creates a transaction that sends the specified amount to the given addresses.
    /// The transaction is signed but not broadcast to the network.
    ///
    /// # Arguments
    ///
    /// * `to_addresses` - The destination Bitcoin addresses
    /// * `amounts` - Amounts to send in satoshis
    /// * `fee_rate` - Optional fee rate in satoshis per virtual byte
    ///
    /// # Returns
    ///
    /// A `Result` containing the signed transaction or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tx = wallet.send_to_address_tx(
    ///     vec!["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"],
    ///     vec![100000], // 0.001 BTC in satoshis
    ///     Some(5), // 5 sat/vB fee rate
    /// )?;
    /// println!("Transaction created: {}", tx.compute_txid());
    /// ```
    fn send_to_address_tx(
        &mut self,
        to_addresses: Vec<&str>,
        amounts: Vec<u64>,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
        let mut psbt = {
            let mut builder = self.bdk_wallet.build_tx();
            builder
                // This is important to ensure the order of the outputs is the same as the one used in the builder
                // default is TxOrdering::Shuffle
                .ordering(TxOrdering::Untouched);
            for (addr, amount) in to_addresses.iter().zip(amounts.iter()) {
                // convert to address
                let to_address = Address::from_str(addr)?.require_network(self.network)?;
                builder.add_recipient(to_address.script_pubkey(), Amount::from_sat(*amount));
            }
            if let Some(fee_rate) = fee_rate {
                builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate).expect("valid feerate"));
            }
            builder.finish()? //Returns a PartialSignedBitcoinTransaction https://docs.rs/bitcoin/0.32.6/bitcoin/psbt/struct.Psbt.html
        };
        // Sign the transaction
        let finalized = self.bdk_wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized, "we should have signed all the inputs");
        // Persist the wallet to the database to avoid change address reuse
        self.persist_wallet()?;
        // Get the transaction from the psbt
        let tx = psbt.extract_tx().expect("tx");
        Ok(tx)
    }

    fn process_batch(
        batch: Vec<Destination>,
        network: Network,
    ) -> Result<(Vec<String>, Vec<u64>), WalletError> {
        if batch.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut addresses: Vec<String> = Vec::new();
        let mut amounts: Vec<u64> = Vec::new();

        for dest in batch {
            match dest {
                Destination::Address(addr, amount) => {
                    addresses.push(addr);
                    amounts.push(amount);
                }
                Destination::P2WPKH(pubkey, amount) => {
                    let addr = pub_key_to_p2wpkh(&pubkey, network)?;
                    addresses.push(addr.to_string());
                    amounts.push(amount);
                }
                Destination::Batch(nested_batch) => {
                    let (nested_addresses, nested_amounts) =
                        Wallet::process_batch(nested_batch, network)?;
                    addresses.extend(nested_addresses);
                    amounts.extend(nested_amounts);
                }
                Destination::P2TR(x_public_key, tap_leaves, amount) => {
                    let address = pub_key_to_p2tr(&x_public_key, &tap_leaves, network)?;
                    addresses.push(address.to_string());
                    amounts.push(amount);
                }
            }
        }

        Ok((addresses, amounts))
    }

    /// Creates a Bitcoin transaction to a specified destination without broadcasting it.
    ///
    /// This method constructs a transaction based on the provided [`Destination`], which
    /// can be a single address, a P2WPKH public key, or a batch of multiple destinations.
    /// Unlike [`send_funds`](#method.send_funds), this function does not broadcast the
    /// transaction to the Bitcoin network—it only creates and returns the transaction object.
    ///
    /// # Arguments
    ///
    /// * `destination` - A [`Destination`] enum specifying where to send funds:
    ///   - `Destination::Address(String, u64)` — send to a raw Bitcoin address and amount (in satoshis).
    ///   - `Destination::P2WPKH(PublicKey, u64)` — convert a public key into a P2WPKH address and send the specified amount.
    ///   - `Destination::Batch(Vec<Destination>)` — recursively process a batch of multiple destinations.
    /// * `fee_rate` - Optional fee rate in satoshis per virtual byte. If `None`,
    ///   the wallet will use its default fee estimation.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing:
    /// * `Ok(Transaction)` - The constructed transaction ready to be signed and broadcasted
    /// * `Err(WalletError)` - If address conversion fails, insufficient funds,
    ///   invalid inputs, or other wallet operations fail
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The provided address is invalid
    /// * A public key cannot be converted into a valid P2WPKH address
    /// * The wallet does not have sufficient funds to cover the amounts and fees
    /// * The batch destination contains invalid entries
    /// * The fee rate is invalid
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_bitvmx_wallet::{Wallet, Destination};
    /// # use bitcoin::PublicKey;
    /// # let mut wallet = Wallet::new(/* ... */).unwrap();
    ///
    /// // Send 50,000 sats to a raw address
    /// let destination = Destination::Address("bcrt1qxyz...".to_string(), 50_000);
    /// let tx = wallet.create_tx(destination, Some(5)).unwrap();
    /// println!("Created transaction: {}", tx.txid());
    ///
    /// // Send to a P2WPKH derived from a public key
    /// # let pubkey = PublicKey::from_str("...").unwrap();
    /// let destination = Destination::P2WPKH(pubkey, 75_000);
    /// let tx = wallet.create_tx(destination, None).unwrap();
    /// println!("Created P2WPKH transaction: {}", tx.txid());
    ///
    /// // Send to multiple destinations in a batch
    /// let batch = vec![
    ///     Destination::Address("bcrt1qabc...".to_string(), 25_000),
    ///     Destination::P2WPKH(pubkey, 10_000),
    /// ];
    /// let destination = Destination::Batch(batch);
    /// let tx = wallet.create_tx(destination, Some(3)).unwrap();
    /// println!("Created batch transaction: {}", tx.txid());
    /// ```
    pub fn create_tx(
        &mut self,
        destination: Destination,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        match destination {
            Destination::Address(address, amount) => {
                self.send_to_address_tx(vec![address.as_str()], vec![amount], fee_rate)
            }
            Destination::P2WPKH(pubkey, amount) => {
                let address = pub_key_to_p2wpkh(&pubkey, self.network)?;
                self.send_to_address_tx(vec![address.to_string().as_str()], vec![amount], fee_rate)
            }
            Destination::Batch(batch) => {
                let (addresses, amounts): (Vec<String>, Vec<u64>) =
                    Wallet::process_batch(batch, self.network)?;

                self.send_to_address_tx(
                    addresses.iter().map(|address| address.as_str()).collect(),
                    amounts,
                    fee_rate,
                )
            }
            Destination::P2TR(x_public_key, tap_leaves, amount) => {
                let address = pub_key_to_p2tr(&x_public_key, &tap_leaves, self.network)?;
                self.send_to_address_tx(vec![address.to_string().as_str()], vec![amount], fee_rate)
            }
        }
    }

    /// Creates and broadcasts a Bitcoin transaction to the specified destination.
    ///
    /// This method builds a transaction based on the provided [`Destination`], signs it
    /// with the wallet's available UTXOs, and broadcasts it to the Bitcoin network.
    /// Unlike [`create_tx`](#method.create_tx), which only constructs a transaction object,
    /// this function finalizes and submits the transaction for propagation.
    ///
    /// # Arguments
    ///
    /// * `destination` - A [`Destination`] enum specifying where to send funds:
    ///   - `Destination::Address(String, u64)` — send to a raw Bitcoin address and amount (in satoshis).
    ///   - `Destination::P2WPKH(PublicKey, u64)` — convert a public key into a P2WPKH address and send the specified amount.
    ///   - `Destination::Batch(Vec<Destination>)` — recursively process a batch of multiple destinations.
    /// * `fee_rate` - Optional fee rate in satoshis per virtual byte. If `None`,
    ///   the wallet will use its default fee estimation.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing:
    /// * `Ok(Transaction)` - The successfully created, signed, and broadcasted transaction
    /// * `Err(WalletError)` - If transaction creation, signing, or broadcasting fails
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The provided address is invalid
    /// * A public key cannot be converted into a valid P2WPKH address
    /// * The wallet does not have sufficient funds to cover the amounts and fees
    /// * The batch destination contains invalid entries
    /// * Transaction signing fails
    /// * Broadcasting to the network fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_bitvmx_wallet::{Wallet, Destination};
    /// # use bitcoin::PublicKey;
    /// # let mut wallet = Wallet::new(/* ... */).unwrap();
    ///
    /// // Send 50,000 sats to a raw address and broadcast it
    /// let destination = Destination::Address("bcrt1qxyz...".to_string(), 50_000);
    /// let tx = wallet.send_funds(destination, Some(5)).unwrap();
    /// println!("Broadcasted transaction: {}", tx.txid());
    ///
    /// // Send 75,000 sats to a P2WPKH derived from a public key
    /// # let pubkey = PublicKey::from_str("...").unwrap();
    /// let destination = Destination::P2WPKH(pubkey, 75_000);
    /// let tx = wallet.send_funds(destination, None).unwrap();
    /// println!("Broadcasted P2WPKH transaction: {}", tx.txid());
    ///
    /// // Send to multiple destinations in a batch
    /// let batch = vec![
    ///     Destination::Address("bcrt1qabc...".to_string(), 25_000),
    ///     Destination::P2WPKH(pubkey, 10_000),
    /// ];
    /// let destination = Destination::Batch(batch);
    /// let tx = wallet.send_funds(destination, Some(3)).unwrap();
    /// println!("Broadcasted batch transaction: {}", tx.txid());
    /// ```
    pub fn send_funds(
        &mut self,
        destination: Destination,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        let tx = self.create_tx(destination, fee_rate)?;
        // Broadcast the transaction and update the wallet with the unconfirmed transaction
        info!(
            "send_funds: Broadcasting transaction: {}",
            tx.compute_txid()
        );
        self.send_transaction(&tx)?;
        Ok(tx)
    }

    /// Send a transaction and update the wallet with the unconfirmed transaction
    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<Txid, WalletError> {
        let tx_hash = self.rpc_client.send_raw_transaction(tx)?;
        // Sync the wallet to update transactions in the mempool
        let last_seen_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.bdk_wallet
            .apply_unconfirmed_txs(vec![(tx.clone(), last_seen_timestamp)]);
        Ok(tx_hash)
    }

    pub fn update_with_tx(&mut self, tx: &Transaction) -> Result<(), WalletError> {
        let last_seen_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.bdk_wallet
            .apply_unconfirmed_txs(vec![(tx.clone(), last_seen_timestamp)]);
        self.persist_wallet()?;
        Ok(())
    }

    pub fn get_wallet_tx(&self, txid: Txid) -> Result<Option<WalletTx<'_>>, WalletError> {
        let tx = self.bdk_wallet.get_tx(txid);
        Ok(tx)
    }

    pub fn list_unspent(&self) -> Result<Vec<LocalOutput>, WalletError> {
        let unspent = self.bdk_wallet.list_unspent().collect::<Vec<_>>();
        Ok(unspent)
    }

    pub fn cancel_tx(&mut self, tx: &Transaction) -> Result<(), WalletError> {
        self.bdk_wallet.cancel_tx(tx);
        self.persist_wallet()?;
        Ok(())
    }

    pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
        self.bdk_wallet.build_tx()
    }

    pub fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> Result<bool, WalletError> {
        let finalized = self.bdk_wallet.sign(psbt, sign_options)?;
        Ok(finalized)
    }

    pub fn tick(&mut self) -> Result<u64, WalletError> {
        let mut blocks_received = 0_u64;
        let mut emitter = self.create_emitter();
        if let Some(emission) = emitter.next_block()? {
            // There is a new block to sync
            self.sync_block(emission)?;
            blocks_received += 1;
        } else {
            // There is no new block to sync, so we sync the mempool
            // self.sync_mempool(emitter.mempool()?)?;
            // The wallet is ready to be used
            self.is_ready = true;
        }
        Ok(blocks_received)
    }

    pub fn sync_block(&mut self, block_emission: BlockEvent<Block>) -> Result<(), WalletError> {
        let height = block_emission.block_height();
        let connected_to = block_emission.connected_to();
        self.bdk_wallet
            .apply_block_connected_to(&block_emission.block, height, connected_to)?;
        self.persist_wallet()?;
        debug!(
            "Applied block {} at height {}",
            block_emission.block_hash(),
            height
        );
        Ok(())
    }

    pub fn sync_mempool(&mut self, mempool_emission: MempoolEvent) -> Result<(), WalletError> {
        self.bdk_wallet.apply_evicted_txs(mempool_emission.evicted);
        self.bdk_wallet
            .apply_unconfirmed_txs(mempool_emission.update);
        self.persist_wallet()?;
        trace!("Applied evicted and unconfirmed transactions");
        Ok(())
    }

    pub fn sync_wallet(&mut self) -> Result<u64, WalletError> {
        info!("Syncing wallet ...");
        let start_sync = Instant::now();
        let mut emitter = self.create_emitter();
        let mut blocks_received = 0_u64;
        while let Some(emission) = emitter.next_block()? {
            blocks_received += 1;
            self.sync_block(emission)?;
        }
        info!(
            "Synced wallet: {} blocks in {}s",
            blocks_received,
            start_sync.elapsed().as_secs_f32(),
        );

        let start_sync = Instant::now();
        // self.sync_mempool(emitter.mempool()?)?;
        info!(
            "Synced wallet: mempool in {}s",
            start_sync.elapsed().as_secs_f32(),
        );
        self.is_ready = true;
        Ok(blocks_received)
    }

    pub fn sync_wallet_multi_thread(&mut self) -> Result<u64, WalletError> {
        let start_sync = Instant::now();
        info!("Syncing wallet with multi thread ...");
        let (sender, receiver) = channel::<Emission>();
        let sender = Arc::new(sender);

        // Handle SIGTERM
        {
            let signal_sender = Arc::clone(&sender);
            let _ = ctrlc::set_handler(move || {
                signal_sender
                    .send(Emission::SigTerm)
                    .expect("Sync wallet error: failed to send SIGTERM")
            });
        } // <- signal_sender is destroyed when exiting the block

        // Create the emitter (producer) thread
        let mut emitter = self.create_emitter();
        let emitter_handle = spawn(move || -> Result<(), WalletError> {
            while let Some(emission) = emitter.next_block()? {
                sender.send(Emission::Block(emission))?;
            }
            sender.send(Emission::Mempool(emitter.mempool()?))?;
            Ok(())
        });

        // Consumer thread
        let mut blocks_received = 0_u64;
        {
            for emission in receiver {
                match emission {
                    Emission::SigTerm => {
                        panic!("SIGTERM received, exiting...");
                    }
                    Emission::Block(block_emission) => {
                        blocks_received += 1;
                        self.sync_block(block_emission)?;
                    }
                    Emission::Mempool(event) => {
                        self.sync_mempool(event)?;
                        break;
                    }
                }
            }
        } // <- receiver is destroyed when exiting the block

        // Wait for emitter thread to finish and check for errors
        match emitter_handle.join() {
            Ok(Ok(_)) => {
                info!(
                    "Synced wallet with multi thread: {} blocks and mempool in {}s",
                    blocks_received,
                    start_sync.elapsed().as_secs_f32(),
                );
                self.is_ready = true;
                Ok(blocks_received)
            }
            Ok(Err(e)) => Err(e),
            Err(e) => Err(WalletError::ThreadPanicked(format!(
                "Sync wallet error: Emitter thread panicked with: {e:?}"
            ))),
        }
    }

    fn create_emitter(&self) -> Emitter<Arc<Client>> {
        // Obtain latest checkpoint (last synced block height and hash)
        let wallet_tip = self.bdk_wallet.latest_checkpoint();
        let wallet_unconfirmed_txs = self
            .bdk_wallet
            .transactions()
            .filter(|tx| tx.chain_position.is_unconfirmed());
        Emitter::new(
            self.rpc_client.clone(),
            wallet_tip,
            self.start_height,
            wallet_unconfirmed_txs,
        )
    }

    fn ensure_db_directory(db_path: &str) -> Result<(), WalletError> {
        let path = Path::new(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn persist_wallet(&mut self) -> Result<(), WalletError> {
        self.bdk_wallet.persist(&mut self.conn)?;
        Ok(())
    }
}

/// Extension trait for regtest-specific wallet functions
/// This trait provides utilities that are only available in regtest mode
pub trait RegtestWallet {
    /// Check if the wallet is in regtest mode
    fn check_network(&self) -> Result<(), WalletError>;

    /// Export the wallet
    fn export_wallet(&self) -> Result<(Vec<String>, Vec<String>), WalletError>;

    /// Generate blocks and send the coinbase reward to a specific address
    /// Returns the coinbase transactions
    /// This function is only available in regtest mode
    fn mine_to_address(
        &self,
        num_blocks: u64,
        address: &str,
    ) -> Result<Vec<Transaction>, WalletError>;

    /// Generate a specified number of blocks to a default address
    /// Returns the coinbase transactions
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Transaction>, WalletError>;

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), WalletError>;

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    #[deprecated(since = "0.2.0", note = "Use `fund_destination` instead")]
    fn fund_address(&mut self, to_address: &str, amount: u64) -> Result<Transaction, WalletError>;

    /// Send funds to a specific destination and mines 1 block
    /// This function is only available in regtest mode
    fn fund_destination(&mut self, destination: Destination) -> Result<Transaction, WalletError>;

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), WalletError>;
}

impl RegtestWallet for Wallet {
    fn check_network(&self) -> Result<(), WalletError> {
        if self.network != Network::Regtest {
            use crate::wallet::errors::WalletError;

            return Err(WalletError::RegtestOnly);
        }
        Ok(())
    }

    fn export_wallet(&self) -> Result<(Vec<String>, Vec<String>), WalletError> {
        let mut private_keys = Vec::new();
        let mut public_keys = Vec::new();
        let keymap = self
            .bdk_wallet
            .get_signers(KeychainKind::External)
            .as_key_map(self.bdk_wallet.secp_ctx());
        for (public_des, private_des) in keymap {
            private_keys.push(private_des.to_string());
            public_keys.push(public_des.to_string());
        }
        Ok((public_keys, private_keys))
    }

    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(
        &self,
        num_blocks: u64,
        address: &str,
    ) -> Result<Vec<Transaction>, WalletError> {
        self.check_network()?;

        let address = Address::from_str(address)?.require_network(self.network)?;
        let block_hashes = self.rpc_client.generate_to_address(num_blocks, &address)?;

        // Convert block hashes to coinbase transactions
        let mut coinbase_txs = Vec::new();
        for block_hash in block_hashes {
            let block = self.rpc_client.get_block(&block_hash)?;
            if let Some(coinbase_tx) = block.txdata.first() {
                coinbase_txs.push(coinbase_tx.clone());
            }
        }

        Ok(coinbase_txs)
    }

    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Transaction>, WalletError> {
        self.check_network()?;
        // Use a different address for mining to avoid conflicts with the receive address
        let address = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";
        self.mine_to_address(num_blocks, address)
    }

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), WalletError> {
        self.check_network()?;

        let address = self.receive_address()?;
        // Mine 1 block to the receive address to get 50 BTC
        self.mine_to_address(3, &address.to_string())?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(100)?;
        // Sync the wallet with the Bitcoin node to the latest block and mempool
        self.sync_wallet()?;

        Ok(())
    }

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, to_address: &str, amount: u64) -> Result<Transaction, WalletError> {
        self.check_network()?;

        // Mine 1 block to the receive address
        let tx = self.send_funds(Destination::Address(to_address.to_string(), amount), None)?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(1)?;
        // Sync the wallet with the Bitcoin node to the latest block and mempool
        self.sync_wallet()?;

        Ok(tx)
    }

    /// Send funds to a specific destination and mines 1 block
    /// This function is only available in regtest mode
    fn fund_destination(&mut self, destination: Destination) -> Result<Transaction, WalletError> {
        self.check_network()?;

        // Mine 1 block to the receive address
        let tx = self.send_funds(destination, None)?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(1)?;
        // Sync the wallet with the Bitcoin node to the latest block and mempool
        self.sync_wallet()?;

        Ok(tx)
    }

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), WalletError> {
        let db_path = Path::new(&wallet_config.db_path);
        info!("Clearing db at {}", db_path.display());
        if db_path.exists() {
            std::fs::remove_file(db_path)?;
        }

        Ok(())
    }
}
