use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

#[derive(Deserialize, Debug, Clone)]
pub struct ClassicWalletConfig {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
}

impl ClassicWalletConfig {
    pub fn new(
        bitcoin: RpcConfig,
        key_manager: KeyManagerConfig,
        key_storage: StorageConfig,
        storage: StorageConfig,
    ) -> Result<ClassicWalletConfig, anyhow::Error> {
        Ok(ClassicWalletConfig {
            bitcoin,
            key_manager,
            key_storage,
            storage,
        })
    }
}
