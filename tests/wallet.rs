
#![cfg(test)]
use bitvmx_wallet::wallet::{Wallet, RegtestWallet};
use bitvmx_wallet::config::Config;
use bitcoin::{Address, Amount, Network, PublicKey, ScriptBuf};

use bdk_wallet::{SignOptions, TxOrdering};

use anyhow::{Ok, Result};
use bitcoind::bitcoind::Bitcoind;
use tracing_subscriber::EnvFilter;
use std::{str::FromStr, sync::Once};

static INIT: Once = Once::new();
const P2WPKH_FEE_RATE: u64 = 141;
const COINBASE_AMOUNT: u64 = 50;

pub fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
}

fn config_trace_aux() {
    let default_modules = ["info", "bitcoincore_rpc=off", "hyper=off","bollard=off"];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

fn clean_and_load_config(config_path: &str) -> Result<Config, anyhow::Error> {
    config_trace();

    let config = bitvmx_settings::settings::load_config_file::<Config>(Some(
        config_path.to_string(),
    ))?;

    Wallet::clear_db(&config.wallet)?;

    Ok(config)
}

#[test]
#[ignore]
fn test_bdk_wallet() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut wallet = Wallet::new(config.bitcoin.clone(), config.wallet.clone())?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;
    // Now it's safe to show the user their next address!
    println!("Your new bdk_wallet receive address is: {}", receive_address);

    // Check the balance of the wallet
    let balance = wallet.balance();
    println!("Wallet balance before syncing: {}", balance.total());
    
    // Send 300 BTC to the wallet using the RegtestWallet trait
    wallet.mine_to_address(6, &receive_address.to_string())?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total(), "Balance should be the same until we sync the wallet");

    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() + Amount::from_int_btc(300), "Balance should have increased by 300 BTC after syncing the wallet");

    // Mine additional blocks to ensure coinbase maturity (100 confirmations required for coinbase)
    // The coinbase outputs from the 6 blocks we just mined need 100 confirmations
    wallet.mine(6)?;
    // Sync the wallet to the latest block to ensure the coinbase outputs are mature otherwise the transaction will fail
    wallet.sync_wallet()?;

    let balance = wallet.balance();
    assert_eq!(balance.total(), new_balance.total(), "Balance should be the same after syncing the wallet");
    
    // Build a transaction to send 44000 satoshis to a taproot address
    let amount_to_send = Amount::from_sat(44_000);
    wallet.send_to_address("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw", amount_to_send.to_sat(), None)?;

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    // Check the balance of the wallet
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE), "Balance should have decreased by 44000 satoshis and fees after syncing the wallet");

    bitcoind.stop()?;
    Ok(())
}


#[test]
#[ignore]
fn test_bdk_wallet_balance() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut wallet = Wallet::new(config.bitcoin.clone(), config.wallet.clone())?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;

    // Check the balance of the wallet
    let balance = wallet.balance();

    // ====== Balance from a coinbase ======
    
    // Send 300 BTC to the wallet using the RegtestWallet trait
    wallet.mine_to_address(6, &receive_address.to_string())?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total(), "Total balance should be the same until we sync the wallet");
    assert_eq!(new_balance.confirmed, Amount::from_int_btc(0), "Confirmed balance should be 0 BTC");
    assert_eq!(new_balance.immature, Amount::from_int_btc(0), "Immature balance should be 0 BTC");
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_int_btc(0), "Unconfirmed balance should be 0 BTC");

    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() +  Amount::from_int_btc(300), "Total balance shows unconfirmed and immature balance");        
    assert_eq!(new_balance.confirmed, Amount::from_int_btc(0), "Confirmed balance should be 0 BTC");
    assert_eq!(new_balance.immature, Amount::from_int_btc(300), "Immature balance should be 300 BTC");
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_int_btc(0), "Unconfirmed balance should be 0 BTC");

    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() + Amount::from_int_btc(300), "Total balance should have increased by 300 BTC after syncing the wallet");
    assert_eq!(new_balance.confirmed, Amount::from_int_btc(300), "Confirmed balance should be 300 BTC");
    assert_eq!(new_balance.immature, Amount::from_int_btc(0), "Immature balance should be 0 BTC");
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_sat(0), "Unconfirmed balance should be 0 BTC");
    
    // ====== Balance from a send to self ======

    let balance = new_balance;
    // send to self to test unconfirmed balance
    let receive_address = wallet.receive_address()?;
    let amount_to_send = Amount::from_int_btc(1);
    wallet.send_to_address(&receive_address.to_string(), amount_to_send.to_sat(), None)?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() - Amount::from_sat(P2WPKH_FEE_RATE), "Total balance should have decreased by the fee rate after syncing the wallet");
    assert_eq!(new_balance.confirmed, Amount::from_int_btc(300) - Amount::from_int_btc(COINBASE_AMOUNT), "Confirmed balance should be 250 BTC as it blocks the whole utxo from the coinbase");
    assert_eq!(new_balance.immature, Amount::from_int_btc(0), "Immature balance should be 0 BTC");
    // Trusted pending balance correspond to the unconfirmed tx to the change address, as we are using a receive address is 0
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_int_btc(COINBASE_AMOUNT) - Amount::from_sat(P2WPKH_FEE_RATE), "Unconfirmed balance should be the change (50 BTC from coinbase utxo - fee rate)");

    let balance = new_balance;
    // Mine 1 block to confirm the transaction
    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total(), "Total balance should be the same after syncing the wallet");
    assert_eq!(new_balance.confirmed, Amount::from_int_btc(300) - Amount::from_sat(P2WPKH_FEE_RATE), "Confirmed balance should be 300 BTC - fee rate");
    assert_eq!(new_balance.immature, Amount::from_int_btc(0), "Immature balance should be 0 BTC");
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_int_btc(0), "Unconfirmed balance should be 0 BTC");

    // ====== Balance from a build tx ======
    let balance = wallet.balance();
    let amount_to_send = Amount::from_int_btc(2);
    let tx = wallet.send_to_address_tx("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw", amount_to_send.to_sat(), None)?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.confirmed, balance.confirmed, "Confirmed balance should be the same after building the transaction");
    assert_eq!(new_balance.immature, balance.immature, "Immature balance should be the same after building the transaction");
    assert_eq!(new_balance.trusted_pending, balance.trusted_pending, "Trusted pending balance should be the same after building the transaction");
    assert_eq!(new_balance.untrusted_pending, balance.untrusted_pending, "Unconfirmed balance should be the same after building the transaction");

    // Broadcast the transaction
    wallet.send_transaction(&tx)?;
    // Sync the wallet with the Bitcoin mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    println!("balance: {:?}", balance);
    println!("new_balance: {:?}", new_balance);
    assert_eq!(new_balance.confirmed, balance.confirmed - tx.output[0].value - tx.output[1].value - Amount::from_sat(P2WPKH_FEE_RATE), "Confirmed balance should have decreased by the amount sent, change and fees");
    assert_eq!(new_balance.immature, balance.immature, "Immature balance should be the same after building the transaction");
    assert_eq!(new_balance.trusted_pending, balance.trusted_pending, "Trusted pending balance should be the same");
    assert_eq!(new_balance.untrusted_pending, tx.output[1].value, "Unconfirmed balance should be the change");

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;
    // Check the balance of the wallet
    let new_balance = wallet.balance();
    println!("new_balance: {:?}", new_balance);
    println!("balance: {:?}", balance);
    assert_eq!(new_balance.confirmed, balance.confirmed - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE), "Confirmed balance should have decreased by the amount sent and fees");
    assert_eq!(new_balance.immature, Amount::from_int_btc(0), "Immature balance should be 0 BTC");
    assert_eq!(new_balance.trusted_pending, Amount::from_int_btc(0), "Trusted pending balance should be 0 BTC");
    assert_eq!(new_balance.untrusted_pending, Amount::from_int_btc(0), "Unconfirmed balance should be 0 BTC");

    bitcoind.stop()?;
    Ok(())
}



#[test]
#[ignore]
fn test_bdk_wallet_build_tx() -> Result<(), anyhow::Error> {
    // Arrenge
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut wallet = Wallet::new(config.bitcoin.clone(), config.wallet.clone())?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;
    
    // Mine 100 blocks to the receive address to ensure only one coinbase output is mature
    wallet.mine_to_address(1, &receive_address.to_string())?;
    wallet.mine(99)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let balance = wallet.balance();
    assert_eq!(balance.trusted_spendable(), Amount::from_int_btc(50), "Balance should be 50 BTC");
    
    // Build a transaction to send 50000 satoshis to a taproot address
    // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
    let to_address = Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")?.require_network(Network::Regtest)?;
    let amount_to_send = Amount::from_sat(50_000);
    let mut psbt = {
        let mut builder = wallet.build_tx();
        builder
            .ordering(TxOrdering::Untouched)
            .add_recipient(to_address.script_pubkey(), amount_to_send);
        builder.finish()? //Returns a PartialSignedBitcoinTransaction https://docs.rs/bitcoin/0.32.6/bitcoin/psbt/struct.Psbt.html
    };
    // Sign the transaction
    // TODO: Use a custom signer using the key manager see
    // https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/signer/index.html
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    assert!(finalized, "we should have signed all the inputs");

    // Get the transaction from the psbt
    let tx = psbt.extract_tx().expect("tx");
    let new_balance = wallet.balance();
    // Broadcast the transaction
    wallet.send_transaction(&tx)?;
    assert_eq!(new_balance.trusted_spendable(), balance.trusted_spendable(), "Balance should not have changed until we sync the wallet");

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    // Sync the wallet with the Bitcoin mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(new_balance.total(), balance.total() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;
    // Check the balance of the wallet
    let new_balance = wallet.balance();
    assert_eq!(new_balance.trusted_spendable(), balance.trusted_spendable() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

    bitcoind.stop()?;
    Ok(())
}

#[test]
#[ignore]
fn test_regtest_wallet() -> Result<(), anyhow::Error> {
    // Arrenge
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut wallet = Wallet::new(config.bitcoin.clone(), config.wallet.clone())?;

    // Mine 101 blocks to the receive address to ensure only one coinbase output is mature
    wallet.fund()?;

    let balance = wallet.balance();
    let amount = Amount::from_sat(50_000);
    let address = Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")?.require_network(Network::Regtest)?;

    let tx = wallet.fund_address(&address.to_string(), amount.to_sat())?;
    let new_balance = wallet.balance();
    assert_eq!(tx.output[0].value, amount, "Output should be 50000 satoshis");
    assert_eq!(tx.output[0].script_pubkey, address.script_pubkey(), "Output should be to the correct address");
    assert_eq!(new_balance.total(), balance.total() - amount - Amount::from_sat(P2WPKH_FEE_RATE), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");
    
    let balance = new_balance;
    let public_key = PublicKey::from_str("020d4bf69a836ddb088b9492af9ce72b39de9ae663b41aa9699fef4278e5ff77b4")?;
    let address = Wallet::pub_key_to_p2wpk(&public_key, Network::Regtest)?;
    println!("address: {:?}", address);
    // Send funds to a specific p2wpkh public key and mines 1 block
    let tx = wallet.fund_p2wpkh(&public_key, amount.to_sat())?;
    println!("p2wpkh tx: {:?}", tx);
    let new_balance = wallet.balance();
    assert_eq!(tx.output[0].value, amount, "Output should be 50000 satoshis");
    assert_eq!(tx.output[0].script_pubkey, ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?), "Output should be to the correct address");
    assert_eq!(new_balance.total(), balance.total() - amount - Amount::from_sat(P2WPKH_FEE_RATE), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

    bitcoind.stop()?;
    Ok(())
}

