use protocol_builder::bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use protocol_builder::key_manager::config::KeyManagerConfig;
use protocol_builder::storage_backend::storage_config::StorageConfig;
use serde::{self, Deserialize};

#[derive(Deserialize, Debug, Clone)]
pub struct ClassicWalletConfig {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}

impl ClassicWalletConfig {
    pub fn new(
        bitcoin: RpcConfig,
        key_manager: KeyManagerConfig,
        storage: StorageConfig,
    ) -> Result<ClassicWalletConfig, anyhow::Error> {
        Ok(ClassicWalletConfig {
            bitcoin,
            key_manager,
            storage,
        })
    }
}
