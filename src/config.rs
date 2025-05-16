use bitcoin::{Network, Txid};
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use config as settings;
use key_manager::config::{KeyManagerConfig};
use protocol_builder::config::ProtocolBuilderConfig;
use serde::{self, Deserialize};
use std::env;
use tracing::warn;

use crate::errors::ConfigError;

static DEFAULT_ENV: &str = "development";
static CONFIG_PATH: &str = "config";

#[derive(Deserialize, Debug)]
pub struct WalletConfig {
    pub network: Network,
    pub dotenv_path: String,
    pub txid: Txid,
    pub vouts: u64, //ToDo: Not read from config
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub wallet: WalletConfig,
    pub rpc: RpcConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
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
        let config_path = format!("{}/{}.json", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings
            .try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }
}
