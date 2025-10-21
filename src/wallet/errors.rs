//! Error types and handling for the BitVMX wallet.
//!
//! This module defines all error types used throughout the wallet system,
//! providing comprehensive error handling and meaningful error messages.

use thiserror::Error;

/// Error types that can occur during wallet operations.
///
/// This enum provides a comprehensive set of error types covering all possible
/// failure scenarios in the wallet system, from configuration errors to
/// Bitcoin network issues.
#[derive(Error, Debug)]
pub enum WalletError {
    /// Configuration-related errors.
    ///
    /// Occurs when there are issues with loading or parsing configuration files.
    #[error("Error while trying to build configuration: {0}")]
    ConfigError(#[from] bitvmx_settings::errors::ConfigError),

    /// Input/Output operation errors.
    ///
    /// Occurs during file system operations, database access, or network I/O.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Protocol builder errors.
    ///
    /// Occurs when there are issues building Bitcoin protocol components.
    #[error("Error while trying to build protocol: {0}")]
    ProtocolBuilderError(#[from] protocol_builder::errors::ProtocolBuilderError),

    /// Protocol builder script errors.
    ///
    /// Occurs when there are issues with Bitcoin script construction.
    #[error("Error on protocol builder script: {0}")]
    ProtocolBuilderScriptError(#[from] protocol_builder::errors::ScriptError),

    /// Key manager errors.
    ///
    /// Occurs during key generation, import, export, or management operations.
    #[error("Error with the key manager: {0}")]
    KeyManagerError(#[from] key_manager::errors::KeyManagerError),

    /// Storage backend errors.
    ///
    /// Occurs during storage operations for keys, wallet data, or metadata.
    #[error("Error with the storage backend: {0}")]
    StoreError(#[from] storage_backend::error::StorageError),

    /// Key identifier already exists error.
    ///
    /// Occurs when trying to create a wallet with an identifier that already exists.
    #[error("Key identifier already exists {0}")]
    KeyAlreadyExists(String),

    /// Key not found error.
    ///
    /// Occurs when trying to access a key or wallet that doesn't exist.
    #[error("Key not found {0}")]
    KeyNotFound(String),

    /// Invalid partial private keys error.
    ///
    /// Occurs when the provided partial private keys are invalid or incomplete.
    #[error("Invalid partial private keys")]
    InvalidPartialPrivateKeys,

    /// Regtest-only operation error.
    ///
    /// Occurs when trying to use regtest-specific functions on non-regtest networks.
    #[error("This function is only available in regtest mode")]
    RegtestOnly,

    /// Thread panic error.
    ///
    /// Occurs when a background thread panics during wallet operations.
    #[error("Thread panicked: {0}")]
    ThreadPanicked(String),

    /// System time error.
    ///
    /// Occurs when there are issues getting the current system time.
    #[error("Error when getting system time: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// Invalid receive key error.
    ///
    /// Occurs when the receive key provided in configuration is invalid or missing.
    #[error("Invalid receive key: {0}")]
    InvalidReceiveKey(String),

    // Bdk Wallet Errors
    /// Bitcoin Core RPC error.
    ///
    /// Occurs during communication with the Bitcoin Core node via RPC.
    #[error("Error with the Bitcoin Core RPC: {0}")]
    BitcoinCoreRpcError(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),

    /// SQLite database error.
    ///
    /// Occurs during SQLite database operations for wallet persistence.
    #[error("Error with the rusqlite: {0}")]
    RusqliteError(#[from] bdk_wallet::rusqlite::Error),

    /// Transaction creation error.
    ///
    /// Occurs when there are issues creating Bitcoin transactions.
    #[error("Error when creating transaction: {0}")]
    CreateTxError(#[from] bdk_wallet::error::CreateTxError),

    /// Transaction signing error.
    ///
    /// Occurs when there are issues signing Bitcoin transactions.
    #[error("Error when signing transaction: {0}")]
    #[allow(deprecated)]
    // TODO: Remove this once the deprecated methods are removed from the BDK wallet
    SignerError(#[from] bdk_wallet::signer::SignerError),

    /// Header application error.
    ///
    /// Occurs when there are issues applying blockchain headers during sync.
    #[error("Error when applying header: {0}")]
    ApplyHeaderError(#[from] bdk_wallet::chain::local_chain::ApplyHeaderError),

    /// Emission sending error.
    ///
    /// Occurs when there are issues sending blockchain events during sync.
    #[error("Error on sync while sending emission: {0}")]
    SendEmissionError(#[from] std::sync::mpsc::SendError<crate::wallet::Emission>),

    /// Descriptor parsing error.
    ///
    /// Occurs when there are issues parsing Bitcoin output descriptors.
    #[error("Error when parsing descriptor: {0}")]
    DescriptorError(#[from] bdk_wallet::descriptor::DescriptorError),

    /// Try send emission error.
    ///
    /// Occurs when there are issues with non-blocking emission sending during sync.
    #[error("Error on sync while sending emission: {0}")]
    TrySendError(#[from] std::sync::mpsc::TrySendError<crate::wallet::Emission>),

    // Boxed errors for large error types
    /// BDK wallet loading error (boxed).
    ///
    /// Occurs when there are issues loading a BDK wallet from persistent storage.
    /// This error is boxed due to its large size as recommended by clippy.
    #[error("Error when loading Bdk wallet on persister {0}")]
    LoadWalletWithPersistError(
        #[from] Box<bdk_wallet::LoadWithPersistError<bdk_wallet::rusqlite::Error>>,
    ),

    /// BDK wallet creation error (boxed).
    ///
    /// Occurs when there are issues creating a new BDK wallet.
    /// This error is boxed due to its large size as recommended by clippy.
    #[error("Error when creating Bdk wallet {0}")]
    CreateWalletError(#[from] Box<bdk_wallet::CreateWithPersistError<bdk_wallet::rusqlite::Error>>),

    // Bitcoin Errors
    /// Bitcoin address parsing error.
    ///
    /// Occurs when there are issues parsing Bitcoin addresses.
    #[error("Error when parsing address: {0}")]
    AddressParseError(#[from] bitcoin::address::ParseError),

    /// Bitcoin address from script error.
    ///
    /// Occurs when there are issues creating addresses from Bitcoin scripts.
    #[error("Error when parsing address from script: {0}")]
    FromScriptError(#[from] bitcoin::address::FromScriptError),

    /// Bitcoin script parsing error.
    ///
    /// Occurs when there are issues parsing Bitcoin scripts.
    #[error("Error when parsing script: {0}")]
    ScriptParseError(#[from] bitcoin::script::Error),

    /// Uncompressed public key error.
    ///
    /// Occurs when trying to use uncompressed public keys where compressed keys are required.
    #[error("Error when parsing uncompressed public key: {0}")]
    UncompressedPublicKeyError(#[from] bitcoin::key::UncompressedPublicKeyError),

    /// WIF private key parsing error.
    ///
    /// Occurs when there are issues parsing private keys in WIF (Wallet Import Format).
    #[error("Error when parsing private key from WIF: {0}")]
    FromWifError(#[from] bitcoin::key::FromWifError),

    /// Invalid URL.
    ///
    /// Occurs when the parsing URL.
    #[error("Invalid URL: {0}. Error: {1}")]
    URLError(String, String),
}
