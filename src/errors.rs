use bitvmx_bitcoin_rpc::errors::BitcoinClientError;
use config as settings;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Error while trying to build configuration")]
    ConfigFileError(#[from] settings::ConfigError),
}

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Error while trying to build wallet")]
    ConfigError(#[from] ConfigError),

    #[error("Error with the Bitcoin client")]
    BitcoinClientError(#[from] BitcoinClientError),

    #[error("Error while trying to build protocol")]
    ProtocolBuilderError(#[from] protocol_builder::errors::ProtocolBuilderError),

    #[error("Error with the key manager")]
    KeyManagerError(#[from] key_manager::errors::KeyManagerError),
}
