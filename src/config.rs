use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

#[derive(Deserialize, Debug)]
pub struct WalletConfig {
    pub bitcoin: RpcConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
}
