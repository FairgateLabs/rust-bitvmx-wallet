use bitvmx_wallet::wallet::{config::Config, RegtestWallet, Wallet};
use std::{path::Path, sync::Once};
use tracing::info;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

pub fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
}

pub fn config_trace_aux() {
    let default_modules = ["info", "bitcoincore_rpc=off", "hyper=off", "bollard=off"];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn clear_db(path: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(path);
    info!("Clearing db at {}", path.display());
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

pub fn clean_and_load_config(config_path: &str) -> Result<Config, anyhow::Error> {
    config_trace();

    let config = protocol_builder::bitvmx_settings::settings::load_config_file::<Config>(Some(
        config_path.to_string(),
    ))?;

    Wallet::clear_db(&config.wallet)?;
    clear_db(&config.storage.path)?;
    clear_db(&config.key_storage.path)?;

    Ok(config)
}
