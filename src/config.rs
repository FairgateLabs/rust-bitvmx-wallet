use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

#[derive(Deserialize, Debug, Clone)]
pub struct WalletConfig {
    pub funding_key: String,
    pub db_path: Option<String>,
}

impl WalletConfig {
    pub fn new(
        funding_key: String,
        db_path: Option<String>,
    ) -> Result<WalletConfig, anyhow::Error> {
        Ok(WalletConfig {
            funding_key,
            db_path,
        })
    }
}


#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
    pub wallet: WalletConfig,
}

impl Config {
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
