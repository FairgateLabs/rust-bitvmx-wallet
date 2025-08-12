#![cfg(test)]
use assert_cmd::Command;
use bitcoind::bitcoind::Bitcoind;
use bitvmx_wallet::config::Config;
use predicates::prelude::*;
use std::path::Path;
use std::sync::Once;
use tracing::info;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

const PROJECT_NAME: &str = "bitvmx-wallet";

pub fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
}

fn config_trace_aux() {
    let default_modules = ["info", "bitcoincore_rpc=off", "hyper=off", "bollard=off"];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

fn load_config(config_path: &str) -> Result<Config, anyhow::Error> {
    let config =
        bitvmx_settings::settings::load_config_file::<Config>(Some(config_path.to_string()))?;

    Ok(config)
}

pub fn clear_db(path: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(path);
    info!("Clearing db at {}", path.display());
    if path.exists() {
        let _ = std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[test]
#[ignore]
fn test_btc_to_sat() -> Result<(), anyhow::Error> {
    config_trace();
    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("btc-to-sat");
    cmd.arg("1");
    cmd.assert().success().stdout(predicate::str::starts_with(
        "Converted 1 BTC to 100000000 Satoshis",
    ));
    Ok(())
}

#[test]
#[ignore]
fn test_unrecognized_subcommand() -> Result<(), anyhow::Error> {
    config_trace();
    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("invalid_argument");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
    Ok(())
}

#[test]
fn test_create_wallet() -> Result<(), anyhow::Error> {
    config_trace();
    let config = load_config("config/regtest.yaml")?;

    // // Clear all wallets, wallet db, storage and key manager
    // let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    // cmd.arg("clear-all-wallets");
    // cmd.assert()
    //     .success()
    //     .stdout(predicate::str::contains("Cleared all wallets"));

    clear_db("/tmp/wallet_manager".as_ref())?;
    clear_db(&config.storage.path)?;
    clear_db(&config.key_storage.path)?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("list-wallets");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallets count: 0"));

    // Create a new wallet
    // This is the first wallet created, so it will use index 0
    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("create-wallet");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "Created new wallet with public_key:"
        )));

    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("list-wallets");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallets count: 1"));

    let mut cmd = Command::cargo_bin(PROJECT_NAME)?;
    cmd.arg("wallet-info");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("Wallet: test-wallet")))
        .stdout(predicate::str::contains("- Balance: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0 BTC, confirmed: 0 BTC }"));

    bitcoind.stop()?;
    Ok(())
}
