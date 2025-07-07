use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Error while trying to build configuration")]
    ConfigError(#[from] bitvmx_settings::errors::ConfigError),

    #[error("Error with the Bitcoin client: {0}")]
    BitcoinClientError(#[from] BitcoinClientError),

    #[error("Error while trying to build protocol")]
    ProtocolBuilderError(#[from] protocol_builder::errors::ProtocolBuilderError),

    #[error("Error with the key manager")]
    KeyManagerError(#[from] key_manager::errors::KeyManagerError),

    #[error("Error with the storage backend")]
    StoreError(#[from] storage_backend::error::StorageError),

    #[error("Funding not found {0} {1}")]
    FundingNotFound(String, String),

    #[error("Funding id not allowed. {0}")]
    FundingIdError(String),

    #[error("Key identifier already exists {0}")]
    KeyAlreadyExists(String),

    #[error("Transfer in progress {0}. Confirm or Revert before using this identifier")]
    TransferInProgress(String),

    #[error("Key not found {0}")]
    KeyNotFound(String),

    #[error("Insufficient funds for: {0}")]
    InsufficientFunds(String),

    #[error("Invalid spending scripts")]
    InvalidSpendingScripts,
}
