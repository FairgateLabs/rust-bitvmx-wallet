use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Error while trying to build configuration")]
    ConfigError(#[from] bitvmx_settings::errors::ConfigError),

    #[error("Error with the Bitcoin client")]
    BitcoinClientError(#[from] BitcoinClientError),

    #[error("Error while trying to build protocol")]
    ProtocolBuilderError(#[from] protocol_builder::errors::ProtocolBuilderError),

    #[error("Error with the key manager")]
    KeyManagerError(#[from] key_manager::errors::KeyManagerError),

    #[error("Error with the storage backend")]
    StoreError(#[from] storage_backend::error::StorageError),

    #[error("Funding not found")]
    FundingNotFound,

    #[error("Insufficient funds")]
    InsufficientFunds,
}
