#![cfg(test)]
mod helper;
use bitcoin::{Address, Amount, Network, PublicKey, ScriptBuf};
use bitvmx_wallet::wallet::{RegtestWallet, Wallet};

use bdk_wallet::{SignOptions, TxOrdering};

use anyhow::Result;
use bitcoind::bitcoind::Bitcoind;
use key_manager::create_key_manager_from_config;
use key_manager::key_store::KeyStore;
use std::rc::Rc;
use std::{str::FromStr};
use storage_backend::storage::Storage;
use crate::helper::clean_and_load_config;

const P2WPKH_FEE_RATE: u64 = 141;
const COINBASE_AMOUNT: u64 = 50;


#[test]
//#[ignore]
fn test_bdk_wallet_sync_wallet() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    // Test sync errors
    // Create a wallet with invalid Bitcoin config
    let mut invalid_bitcoin_config = config.bitcoin.clone();
    invalid_bitcoin_config.url = "http://127.0.0.1:666".to_string(); //invalid port

    let private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let mut wallet = Wallet::from_private_key(
        invalid_bitcoin_config,
        config.wallet.clone(),
        private_key,
        None,
    )?;

    let result  =  wallet.tick();
    assert!(result.is_err(), "Tick one block to invalid Bitcoin node should throw an error");
    let error_description = result.unwrap_err().to_string();
    assert!(
        error_description.contains("Couldn't connect to host: Connection refused"), 
        "Error should contain: Couldn't connect to host: Connection refused, got: {}", 
        format!("Excpected tick error: {:?}", error_description)
    );

    let result  =  wallet.sync_wallet();
    assert!(result.is_err(), "Sync one block to invalid Bitcoin node should throw an error");
    let error_description = result.unwrap_err().to_string();
    assert!(
        error_description.contains("Couldn't connect to host: Connection refused"), 
        "Error should contain:Couldn't connect to host: Connection refused, got: {}", 
        format!("Excpected sync wallet error: {:?}", error_description)
    );

    // TODO: Fix wallet error when using multi thread sync
    // let result  =  wallet.sync_wallet_multi_thread();
    // assert!(result.is_err(), "Sync multi thread to invalid Bitcoin node should throw an error");
    // let error_description = result.unwrap_err().to_string();
    // assert!(
    //     error_description.contains("Couldn't connect to host: Connection refused"), 
    //     "Error should contain:Couldn't connect to host: Connection refused, got: {}", 
    //     format!("Excpected sync wallet multi thread error: {:?}", error_description)
    // );

    // Test successfull sync
    // Start a Bitcoin node
    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    // Create a wallet with correct config and sync it
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    )?;
    assert!(!wallet.is_ready, "Wallet should not be ready on start");

    // Tick for 13 blocks and check that the wallet is not ready
    wallet.mine(13)?;
    for _ in 0..13 {
        let blocks_received  =  wallet.tick()?;
        assert_eq!(blocks_received, 1, "Tick should return 1 block received");
        assert!(!wallet.is_ready, "Wallet should not be ready");
    }
    // Once all blocks are synced, tick should return 0 blocks received and the wallet should be ready
    let blocks_received  =  wallet.tick()?;
    assert_eq!(blocks_received, 0, "Tick should return 0 block received once the wallet is full synced");
    assert!(wallet.is_ready, "Wallet should be ready after full sync");

    wallet.mine(1)?;
    let blocks_received  =  wallet.tick()?;
    assert_eq!(blocks_received, 1, "Tick should return 1 block received if there are blocks to sync after full synced");
    assert!(wallet.is_ready, "Wallet should be ready if there are blocks to sync after full synced");

    let blocks_received  =  wallet.sync_wallet()?;
    assert_eq!(blocks_received, 0, "Sync wallet should return 0 blocks received");

    wallet.mine(13)?;

    let blocks_received  =  wallet.sync_wallet()?;
    assert_eq!(blocks_received, 13, "Sync wallet should return 13 blocks received");

    let blocks_received  =  wallet.sync_wallet_multi_thread()?;
    assert_eq!(blocks_received, 0, "Sync wallet with multi thread should return 0 blocks received");

    wallet.mine(123)?;

    let blocks_received  =  wallet.sync_wallet_multi_thread()?;
    assert_eq!(blocks_received, 123, "Sync wallet with multi thread should return 123 blocks received");

    bitcoind.stop()?;
    Ok(())
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

    let private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    )?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;
    // Check the balance of the wallet
    let balance = wallet.balance();

    // Send 300 BTC to the wallet using the RegtestWallet trait
    wallet.mine_to_address(6, &receive_address.to_string())?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable(),
        "Balance should be the same until we sync the wallet"
    );

    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable() + Amount::from_int_btc(300),
        "Balance should have increased by 300 BTC after syncing the wallet"
    );

    let balance = wallet.balance();
    // Build a transaction to send 44000 satoshis to a taproot address
    let amount_to_send = Amount::from_sat(44_000);
    wallet.send_to_address(
        "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw",
        amount_to_send.to_sat(),
        None,
    )?;

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    // Check the balance of the wallet
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Balance should have decreased by 44000 satoshis and fees after syncing the wallet"
    );
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable() - Amount::from_int_btc(50),
        "Trusted Balance should be  "
    );

    bitcoind.stop()?;
    Ok(())
}

#[test]
#[ignore]
fn test_bdk_wallet_load_different_wallet_same_db() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    // Create first wallet and fund it
    let original_private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        original_private_key,
        None,
    )?;
    let original_receive_address = wallet.receive_address()?;
    wallet.mine_to_address(6, &original_receive_address.to_string())?;
    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    wallet.sync_wallet()?;
    let original_wallet_balance = wallet.balance();

    // Load a different wallet from the same database should throw an error
    let private_key = "cQYmfCC4iDtw5V23QLnbUq5zHbSeXZBKMbPd6T5GMJq8fdLy28Jb";
    let result = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    );
    assert!(
        result.is_err(),
        "Loading a different wallet from the same database should throw an error"
    );
    let err = result.err().unwrap();
    let error_description = err.to_string();
    assert!(
        error_description.contains("Descriptor mismatch for External keychain"),
        "Error should contain the descriptor mismatch, got: {}",
        error_description
    );
    assert!(error_description.contains("loaded wpkh(039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef)#75hac2kl"), "Error should contain the loaded descriptor");
    assert!(error_description.contains("expected wpkh(0312fb0fd3b52b4d0dfd387bfd924f875ac20cb3de085aa3bf2f06e2971f86436b)#5cdng3a7"), "Error should contain the expected descriptor");

    // Clear the database and load a different wallet from the same database should work
    Wallet::clear_db(&config.wallet)?;
    wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    )?;
    let receive_address = wallet.receive_address()?;
    wallet.sync_wallet()?;
    let balance = wallet.balance();
    assert_eq!(
        balance.total(),
        Amount::from_int_btc(0),
        "New Wallet Balance should be 0 BTC"
    );

    // Check new wallet works correctly
    // Mine 1 block to the new wallet
    wallet.mine_to_address(1, &receive_address.to_string())?;
    // We don't to wait for coinbase output to be mature as we are not using it, just checking the balance
    wallet.sync_wallet()?;
    let balance = wallet.balance();
    assert_eq!(
        balance.total(),
        Amount::from_int_btc(COINBASE_AMOUNT),
        "Balance of the new wallet should be 50 BTC"
    );

    // Send funds to original wallet
    wallet.mine_to_address(1, &original_receive_address.to_string())?;
    wallet.mine(99)?;
    wallet.sync_wallet()?;

    // Clean the database and load the original wallet should have the updated balance
    Wallet::clear_db(&config.wallet)?;
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        original_private_key,
        None,
    )?;
    wallet.sync_wallet()?;
    let balance = wallet.balance();
    assert_eq!(
        balance.total(),
        original_wallet_balance.total() + Amount::from_int_btc(COINBASE_AMOUNT),
        "Balance should be the same as the original wallet"
    );

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

    let private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    )?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;

    // Check the balance of the wallet
    let balance = wallet.balance();

    // ====== Balance from a coinbase ======

    // Send 300 BTC to the wallet using the RegtestWallet trait
    wallet.mine_to_address(6, &receive_address.to_string())?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total(),
        "Total balance should be the same until we sync the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(0),
        "Confirmed balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(0),
        "Unconfirmed balance should be 0 BTC"
    );

    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() + Amount::from_int_btc(300),
        "Total balance shows unconfirmed and immature balance"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(0),
        "Confirmed balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(300),
        "Immature balance should be 300 BTC"
    );
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(0),
        "Unconfirmed balance should be 0 BTC"
    );

    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() + Amount::from_int_btc(300),
        "Total balance should have increased by 300 BTC after syncing the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(300),
        "Confirmed balance should be 300 BTC"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_sat(0),
        "Unconfirmed balance should be 0 BTC"
    );

    // ====== Balance from a send to self ======

    let balance = new_balance;
    // send to self to test unconfirmed balance
    let receive_address = wallet.receive_address()?;
    let amount_to_send = Amount::from_int_btc(1);
    wallet.send_to_address(&receive_address.to_string(), amount_to_send.to_sat(), None)?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() - Amount::from_sat(P2WPKH_FEE_RATE),
        "Total balance should have decreased by the fee rate after syncing the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(300) - Amount::from_int_btc(COINBASE_AMOUNT),
        "Confirmed balance should be 250 BTC as it blocks the whole utxo from the coinbase"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    // Trusted pending balance correspond to the unconfirmed tx to the change address, as we are using a receive address is 0
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(COINBASE_AMOUNT) - Amount::from_sat(P2WPKH_FEE_RATE),
        "Unconfirmed balance should be the change (50 BTC from coinbase utxo - fee rate)"
    );

    let balance = new_balance;
    // Mine 1 block to confirm the transaction
    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total(),
        "Total balance should be the same after syncing the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(300) - Amount::from_sat(P2WPKH_FEE_RATE),
        "Confirmed balance should be 300 BTC - fee rate"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(0),
        "Unconfirmed balance should be 0 BTC"
    );

    // ====== Balance from a build tx ======
    let balance = wallet.balance();
    let amount_to_send = Amount::from_int_btc(2);
    let tx = wallet.send_to_address_tx(
        "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw",
        amount_to_send.to_sat(),
        None,
    )?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.confirmed, balance.confirmed,
        "Confirmed balance should be the same after building the transaction"
    );
    assert_eq!(
        new_balance.immature, balance.immature,
        "Immature balance should be the same after building the transaction"
    );
    assert_eq!(
        new_balance.trusted_pending, balance.trusted_pending,
        "Trusted pending balance should be the same after building the transaction"
    );
    assert_eq!(
        new_balance.untrusted_pending, balance.untrusted_pending,
        "Unconfirmed balance should be the same after building the transaction"
    );

    // Broadcast the transaction
    wallet.send_transaction(&tx)?;
    // Sync the wallet with the Bitcoin mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    println!("balance: {:?}", balance);
    println!("new_balance: {:?}", new_balance);
    assert_eq!(
        new_balance.confirmed,
        balance.confirmed
            - tx.output[0].value
            - tx.output[1].value
            - Amount::from_sat(P2WPKH_FEE_RATE),
        "Confirmed balance should have decreased by the amount sent, change and fees"
    );
    assert_eq!(
        new_balance.immature, balance.immature,
        "Immature balance should be the same after building the transaction"
    );
    assert_eq!(
        new_balance.trusted_pending, balance.trusted_pending,
        "Trusted pending balance should be the same"
    );
    assert_eq!(
        new_balance.untrusted_pending, tx.output[1].value,
        "Unconfirmed balance should be the change"
    );

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;
    // Check the balance of the wallet
    let new_balance = wallet.balance();
    println!("new_balance: {:?}", new_balance);
    println!("balance: {:?}", balance);
    assert_eq!(
        new_balance.confirmed,
        balance.confirmed - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Confirmed balance should have decreased by the amount sent and fees"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(0),
        "Trusted pending balance should be 0 BTC"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(0),
        "Unconfirmed balance should be 0 BTC"
    );

    bitcoind.stop()?;
    Ok(())
}

#[test]
#[ignore]
fn test_bdk_wallet_balance_with_change_address() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let change_private_key = "cQYmfCC4iDtw5V23QLnbUq5zHbSeXZBKMbPd6T5GMJq8fdLy28Jb";
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        Some(change_private_key),
    )?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;

    // Send 300 BTC to the wallet using the RegtestWallet trait
    let num_blocks = 6;
    wallet.mine_to_address(num_blocks, &receive_address.to_string())?;
    wallet.sync_wallet()?;
    let balance = wallet.balance();
    assert_eq!(
        balance.total(),
        Amount::from_int_btc(COINBASE_AMOUNT * num_blocks),
        "Total balance shows unconfirmed and immature balance"
    );

    // Mine 100 blocks to ensure the coinbase output is mature
    wallet.mine(100)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable() + Amount::from_int_btc(COINBASE_AMOUNT * num_blocks),
        "Trusted spendable balance should have increased by the coinbase amount after syncing the wallet"
    );

    // ====== Balance after send to address and receive change ======

    let balance = new_balance;
    let amount_to_send = Amount::from_int_btc(1);
    let send_to_address = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";
    wallet.send_to_address(send_to_address, amount_to_send.to_sat(), None)?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Total balance should have decreased by the fee rate after syncing the wallet"
    );
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Trusted spendable balance should have decreased by the fee rate after syncing the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(300) - Amount::from_int_btc(COINBASE_AMOUNT),
        "Confirmed balance should be 250 BTC as it blocks the whole utxo from the coinbase"
    );
    assert_eq!(
        new_balance.immature,
        Amount::from_int_btc(0),
        "Immature balance should be 0 BTC"
    );
    // Trusted pending balance correspond to the unconfirmed tx to the change address, as we are using a receive address is 0
    assert_eq!(
        new_balance.trusted_pending,
        Amount::from_int_btc(COINBASE_AMOUNT) - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Trusted pending balance should be the change (50 BTC from coinbase utxo - amount sent - fee rate)"
    );
    assert_eq!(
        new_balance.untrusted_pending,
        Amount::from_int_btc(0),
        "Unconfirmed balance should be 0 BTC"
    );

    let balance = new_balance;
    // Mine 1 block to confirm the transaction
    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total(),
        "Total balance should be the same after syncing the wallet"
    );
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable(),
        "Trusted spendable balance should be the same after syncing the wallet"
    );
    assert_eq!(
        new_balance.confirmed,
        Amount::from_int_btc(300) - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Confirmed balance should be 300 BTC - amount sent - fee rate"
    );

    bitcoind.stop()?;
    Ok(())
}

#[test]
#[ignore]
fn test_bdk_wallet_build_tx() -> Result<(), anyhow::Error> {
    let config = clean_and_load_config("config/regtest.yaml")?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    let mut wallet = Wallet::from_private_key(
        config.bitcoin.clone(),
        config.wallet.clone(),
        private_key,
        None,
    )?;

    // Get a new address to receive bitcoin.
    let receive_address = wallet.receive_address()?;

    // Mine 100 blocks to the receive address to ensure only one coinbase output is mature
    wallet.mine_to_address(1, &receive_address.to_string())?;
    wallet.mine(99)?;
    // Sync the wallet with the Bitcoin node to the latest block and mempool
    wallet.sync_wallet()?;

    let balance = wallet.balance();
    assert_eq!(
        balance.trusted_spendable(),
        Amount::from_int_btc(50),
        "Balance should be 50 BTC"
    );

    // Build a transaction to send 50000 satoshis to a taproot address
    // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
    let to_address = Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")?
        .require_network(Network::Regtest)?;
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
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable(),
        "Balance should not have changed until we sync the wallet"
    );

    // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

    // Sync the wallet with the Bitcoin mempool
    wallet.sync_wallet()?;
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.total(),
        balance.total() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Balance should have decreased by 50000 satoshis and fees after syncing the wallet"
    );

    wallet.mine(1)?;
    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;
    // Check the balance of the wallet
    let new_balance = wallet.balance();
    assert_eq!(
        new_balance.trusted_spendable(),
        balance.trusted_spendable() - amount_to_send - Amount::from_sat(P2WPKH_FEE_RATE),
        "Balance should have decreased by 50000 satoshis and fees after syncing the wallet"
    );

    bitcoind.stop()?;
    Ok(())
}

#[test]
#[ignore]
fn test_regtest_wallet() -> Result<(), anyhow::Error> {
    // Arrenge
    let config = clean_and_load_config("config/regtest.yaml")?;
    let storage = Rc::new(Storage::new(&config.storage)?);
    let key_store = KeyStore::new(storage.clone());
    let key_manager = Rc::new(create_key_manager_from_config(
        &config.key_manager,
        key_store,
        storage.clone(),
    )?);

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    bitcoind.start()?;

    let mut wallet = Wallet::from_derive_keypair(
        config.bitcoin.clone(),
        config.wallet.clone(),
        key_manager.clone(),
        0,
        Some(1),
    )?;

    // Mine 101 blocks to the receive address to ensure only one coinbase output is mature
    wallet.fund()?;

    let balance = wallet.balance();
    let amount = Amount::from_sat(50_000);
    let address = Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")?
        .require_network(Network::Regtest)?;

    let tx = wallet.fund_address(&address.to_string(), amount.to_sat())?;
    let new_balance = wallet.balance();
    assert_eq!(
        tx.output[0].value, amount,
        "Output should be 50000 satoshis"
    );
    assert_eq!(
        tx.output[0].script_pubkey,
        address.script_pubkey(),
        "Output should be to the correct address"
    );
    assert_eq!(
        new_balance.total(),
        balance.total() - amount - Amount::from_sat(P2WPKH_FEE_RATE),
        "Balance should have decreased by 50000 satoshis and fees after syncing the wallet"
    );

    let balance = new_balance;
    let public_key =
        PublicKey::from_str("020d4bf69a836ddb088b9492af9ce72b39de9ae663b41aa9699fef4278e5ff77b4")?;
    let address = Wallet::pub_key_to_p2wpk(&public_key, Network::Regtest)?;
    println!("address: {:?}", address);
    // Send funds to a specific p2wpkh public key and mines 1 block
    let tx = wallet.fund_p2wpkh(&public_key, amount.to_sat())?;
    println!("p2wpkh tx: {:?}", tx);
    let new_balance = wallet.balance();
    assert_eq!(
        tx.output[0].value, amount,
        "Output should be 50000 satoshis"
    );
    assert_eq!(
        tx.output[0].script_pubkey,
        ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?),
        "Output should be to the correct address"
    );
    assert_eq!(
        new_balance.total(),
        balance.total() - amount - Amount::from_sat(P2WPKH_FEE_RATE),
        "Balance should have decreased by 50000 satoshis and fees after syncing the wallet"
    );

    bitcoind.stop()?;
    Ok(())
}
