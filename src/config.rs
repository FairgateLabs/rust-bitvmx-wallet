use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

#[derive(Deserialize, Debug, Clone)]
pub struct WalletConfig {
    pub db_path: String,
    pub start_height: Option<u32>,
    pub receive_key: Option<String>,
    pub change_key: Option<String>,
}

impl WalletConfig {
    pub fn new(db_path: String, start_height: Option<u32>, receive_key: Option<String>, change_key: Option<String>) -> Result<WalletConfig, anyhow::Error> {
        Ok(WalletConfig {
            db_path,
            start_height,
            receive_key,
            change_key,
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
