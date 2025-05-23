use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use protocol_builder::config::ProtocolBuilderConfig;
use serde::{self, Deserialize};
use storage_backend::storage_config::StorageConfig;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
}

#[derive(Deserialize, Debug)]
pub struct WalletConfig {
    pub private_key: String,
}

impl WalletConfig {
    pub fn new(private_key: String) -> Self {
        Self { private_key }
    }
}
