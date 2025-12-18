#![cfg(test)]
mod helper;
use crate::helper::{clean_and_load_config, clear_db};
use assert_cmd::{cargo::cargo_bin, Command};
use bitcoind::bitcoind::Bitcoind;
use predicates::prelude::*;

fn get_cmd() -> Command {
    Command::new(cargo_bin!("wallet"))
}

#[test]
#[ignore]
fn test_btc_to_sat() -> Result<(), anyhow::Error> {
    // Clear all wallets, wallet db, storage and key manager
    clear_db("/tmp/wallet_manager".as_ref())?;
    clean_and_load_config("config/regtest.yaml")?;

    let mut cmd = get_cmd();
    cmd.arg("btc-to-sat");
    cmd.arg("1");
    cmd.assert().success().stdout(predicate::str::contains(
        "Converted 1 BTC to 100000000 Satoshis",
    ));
    Ok(())
}

#[test]
#[ignore]
fn test_unrecognized_subcommand() -> Result<(), anyhow::Error> {
    // Clear all wallets, wallet db, storage and key manager
    clear_db("/tmp/wallet_manager".as_ref())?;
    clean_and_load_config("config/regtest.yaml")?;

    let mut cmd = get_cmd();
    cmd.arg("invalid_argument");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
    Ok(())
}

#[test]
#[ignore]
fn test_create_wallet() -> Result<(), anyhow::Error> {
    // Clear all wallets, wallet db, storage and key manager
    clear_db("/tmp/wallet_manager".as_ref())?;
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "bitcoin/bitcoin:29.1",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut cmd = get_cmd();
    cmd.arg("list-wallets");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallets count: 0"));

    // Create a new wallet
    // This is the first wallet created, so it will use index 0
    let mut cmd = get_cmd();
    cmd.arg("create-wallet");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "Created new wallet with public_key:"
        )));

    let mut cmd = get_cmd();
    cmd.arg("list-wallets");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallets count: 1"));

    let mut cmd = get_cmd();
    cmd.arg("wallet-info");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("Wallet: test-wallet")))
        .stdout(predicate::str::contains("- Balance: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0 BTC, confirmed: 0 BTC }"));

    let mut cmd = get_cmd();
    cmd.arg("regtest-fund");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "Wallet test-wallet funded with 150 BTC"
        )));

    let mut cmd = get_cmd();
    cmd.arg("wallet-info");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("Wallet: test-wallet")))
        .stdout(predicate::str::contains("- Balance: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0 BTC, confirmed: 150 BTC }"));

    let mut cmd = get_cmd();
    cmd.arg("send-and-mine");
    cmd.arg("test-wallet");
    cmd.arg("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw");
    cmd.arg("100000000");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("Funded address bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw with amount 100000000 satoshis and mined 1 block")));

    let mut cmd = get_cmd();
    cmd.arg("wallet-info");
    cmd.arg("test-wallet");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("Wallet: test-wallet")))
        .stdout(predicate::str::contains("- Balance: { immature: 0 BTC, trusted_pending: 0 BTC, untrusted_pending: 0 BTC, confirmed: 148.99999859 BTC }"));

    // TODO add test for partial private keys

    // TODO add test for edge cases

    bitcoind.stop()?;
    Ok(())
}
