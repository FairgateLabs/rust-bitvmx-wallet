use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Error while trying to build configuration: {0}")]
    ConfigError(#[from] bitvmx_settings::errors::ConfigError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Error while trying to build protocol: {0}")]
    ProtocolBuilderError(#[from] protocol_builder::errors::ProtocolBuilderError),

    #[error("Error on protocol builder script: {0}")]
    ProtocolBuilderScriptError(#[from] protocol_builder::errors::ScriptError),

    #[error("Error with the key manager: {0}")]
    KeyManagerError(#[from] key_manager::errors::KeyManagerError),

    #[error("Error with the storage backend: {0}")]
    StoreError(#[from] storage_backend::error::StorageError),

    #[error("Key identifier already exists {0}")]
    KeyAlreadyExists(String),

    #[error("Key not found {0}")]
    KeyNotFound(String),

    #[error("Invalid partial private keys")]
    InvalidPartialPrivateKeys,

    #[error("This function is only available in regtest mode")]
    RegtestOnly,

    #[error("Thread panicked: {0}")]
    ThreadPanicked(String),

    #[error("Error when getting system time: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    // Bdk Wallet Errors
    #[error("Error with the Bitcoin Core RPC: {0}")]
    BitcoinCoreRpcError(#[from] bdk_bitcoind_rpc::bitcoincore_rpc::Error),

    #[error("Error with the rusqlite: {0}")]
    RusqliteError(#[from] bdk_wallet::rusqlite::Error),

    #[error("Error when creating transaction: {0}")]
    CreateTxError(#[from] bdk_wallet::error::CreateTxError),

    #[error("Error when signing transaction: {0}")]
    SignerError(#[from] bdk_wallet::signer::SignerError),

    #[error("Error when applying header: {0}")]
    ApplyHeaderError(#[from] bdk_wallet::chain::local_chain::ApplyHeaderError),

    #[error("Error on sync while sending emission: {0}")]
    SendEmissionError(#[from] std::sync::mpsc::SendError<crate::wallet::Emission>),

    #[error("Error when parsing descriptor: {0}")]
    DescriptorError(#[from] bdk_wallet::descriptor::DescriptorError),

    // Some errors are too large according to clippy https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err
    // So we are using the Boxed representation of the error
    #[error("Error when loading Bdk wallet on persister {0}")]
    LoadWalletWithPersistError(#[from] Box<bdk_wallet::LoadWithPersistError<bdk_wallet::rusqlite::Error>>),

    #[error("Error when creating Bdk wallet {0}")]
    CreateWalletError(#[from] Box<bdk_wallet::CreateWithPersistError<bdk_wallet::rusqlite::Error>>),

    // Bitcoin Errors
    #[error("Error when parsing address: {0}")]
    AddressParseError(#[from] bitcoin::address::ParseError),

    #[error("Error when parsing address from script: {0}")]
    FromScriptError(#[from] bitcoin::address::FromScriptError),

    #[error("Error when parsing script: {0}")]
    ScriptParseError(#[from] bitcoin::script::Error),

    #[error("Error when parsing uncompressed public key: {0}")]
    UncompressedPublicKeyError(#[from] bitcoin::key::UncompressedPublicKeyError),

}
