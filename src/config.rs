use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use config as settings;
use key_manager::config::KeyManagerConfig;
use protocol_builder::config::ProtocolBuilderConfig;
use serde::{self, Deserialize};
use std::env;
use storage_backend::storage_config::StorageConfig;
use tracing::warn;

use crate::errors::ConfigError;

static DEFAULT_ENV: &str = "development";
static CONFIG_PATH: &str = "config";

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub bitcoin: RpcConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
    pub storage: StorageConfig,
}

impl Config {
    pub fn new() -> Result<Config, ConfigError> {
        let env = Config::get_env();
        Config::parse_config(env)
    }

    fn get_env() -> String {
        env::var("BITVMX_ENV").unwrap_or_else(|_| {
            let default_env = DEFAULT_ENV.to_string();
            warn!(
                "BITVMX_ENV not set. Using default environment: {}",
                default_env
            );
            default_env
        })
    }

    fn parse_config(env: String) -> Result<Config, ConfigError> {
        let config_path = format!("{}/{}.yaml", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings
            .try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }
}
