#[allow(unused_imports)]
use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{secp256k1::Secp256k1, Address, Amount, Block, FeeRate, Network, PrivateKey, PublicKey, ScriptBuf, Transaction, Txid, XOnlyPublicKey};

use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use protocol_builder::scripts::{self, ProtocolScript};
use tracing::{debug, info};

use bdk_wallet::{rusqlite::Connection, Balance, KeychainKind, PersistedWallet, SignOptions, TxOrdering, Wallet as BdkWallet};
use ctrlc;
use bdk_bitcoind_rpc::{Emitter, bitcoincore_rpc::{Auth, Client, RpcApi},};
use std::{str::FromStr,sync::{mpsc::sync_channel, Arc}, thread::spawn, fs, path::Path};

#[derive(Debug)]
enum Emission {
    SigTerm,
    Block(bdk_bitcoind_rpc::BlockEvent<Block>),
    Mempool(bdk_bitcoind_rpc::MempoolEvent),
}

pub struct Wallet {
    pub network: bitcoin::Network,
    pub rpc_client: Arc<Client>,
    conn: Connection,
    pub bdk_wallet: PersistedWallet<Connection>,
    pub public_key: String,
}

impl Wallet {
    pub fn new(bitcoin_config: RpcConfig, wallet_config: WalletConfig) -> Result<Wallet, anyhow::Error> {
        // Create a Bitcoin RPC client
        let rpc_client = Arc::new(Client::new(&bitcoin_config.url, Auth::UserPass(bitcoin_config.username.clone(), bitcoin_config.password.clone()))?);

        // Wallet config
        let public_key = Self::private_key_to_public_key(&wallet_config.funding_key)?;
        let db_path = wallet_config.db_path.clone().unwrap_or_else(|| Self::db_path(public_key.to_string()));
        
        // Ensure the directory exists
        Self::ensure_db_directory(&db_path)?;
        // Open or create a new sqlite database.
        let mut conn = Connection::open(db_path)?;

        // Get or create a wallet with initial data read from rusqlite database.
        let bdk_wallet = Self::load_bdk_wallet(&mut conn, bitcoin_config.network, &wallet_config)?;

        Ok(Self {
            network: bitcoin_config.network,
            rpc_client,
            conn,
            bdk_wallet,
            public_key: public_key.to_string(),
        })
    }

    pub fn get_balance(&self) -> Result<Balance, anyhow::Error> {
        let balance = self.bdk_wallet.balance();
        Ok(balance)
    }

    pub fn receive_address(&mut self) -> Result<Address, anyhow::Error> {
        let address_info = self.bdk_wallet.reveal_next_address(KeychainKind::External);
        // Mark previous address as used for receiving and persist to sqlite database.
        self.persist_wallet()?;
        Ok(address_info.address)
    }

    pub fn send_to_address(&mut self, address: &str, amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
        // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
        let to_address = Address::from_str(address)?.assume_checked();
        let mut psbt = {
            let mut builder = self.bdk_wallet.build_tx();
            builder
                // This is important to ensure the order of the outputs is the same as the one used in the builder
                // default is TxOrdering::Shuffle
                .ordering(TxOrdering::Untouched)
                .add_recipient(to_address.script_pubkey(), Amount::from_sat(amount));
            if let Some(fee_rate) = fee_rate {
                builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate).expect("valid feerate"));
            }
            builder.finish()? //Returns a PartialSignedBitcoinTransaction https://docs.rs/bitcoin/0.32.6/bitcoin/psbt/struct.Psbt.html
        };
        // Sign the transaction
        let finalized = self.bdk_wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized, "we should have signed all the inputs");

        // Get the transaction from the psbt
        let tx = psbt.extract_tx().expect("tx");

        // Broadcast the transaction
        self.send_transaction(&tx)?;
        Ok(tx)
    }

    pub fn pub_key_to_p2wpk(&mut self, public_key: &PublicKey) -> Result<Address, anyhow::Error> {
        let script = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);
        let address = Address::from_script(&script, self.network)?;
        Ok(address)
    }

    pub fn send_to_p2wpkh(&mut self, public_key: &PublicKey, amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
        let address = self.pub_key_to_p2wpk(public_key)?;
        let tx = self.send_to_address(&address.to_string(), amount, fee_rate)?;
        Ok(tx)
    }

    pub fn pub_key_to_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript]) -> Result<Address, anyhow::Error> {
        let tap_spend_info = scripts::build_taproot_spend_info(self.bdk_wallet.secp_ctx(), x_public_key, tap_leaves)?;
        let script = ScriptBuf::new_p2tr_tweaked(tap_spend_info.output_key());
        let address = Address::from_script(&script, self.network)?;
        Ok(address)
    }

    pub fn send_to_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript], amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
        let address = self.pub_key_to_p2tr(x_public_key, tap_leaves)?;
        let tx = self.send_to_address(&address.to_string(), amount, fee_rate)?;
        Ok(tx)
    }

    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<Txid, anyhow::Error> {
        let tx_hash = self.rpc_client.send_raw_transaction(tx)?;
        self.sync_wallet()?;
        Ok(tx_hash)
    }

    pub fn cancel_tx(&mut self, tx: &Transaction) -> Result<(), anyhow::Error> {
        self.bdk_wallet.cancel_tx(tx);
        Ok(())
    }

    pub fn sync_wallet(&mut self) -> Result<(), anyhow::Error> {
        // Obtain latest checkpoint (last synced block height and hash)
        let wallet_tip = self.bdk_wallet.latest_checkpoint();
        debug!(
            "Syncing wallet from latest checkpoint: {} at height {}",
            wallet_tip.hash(),
            wallet_tip.height()
        );

        // Create a synchronous channel with two threads one to receive emissions from the emitter and the other to send emissions to the wallet
        // Buffer Size of 21: This means the channel can hold up to 21 Emission messages in its buffer. If the buffer is full the emitter thread will block when trying to send new emissions
        let (sender, receiver) = sync_channel::<Emission>(21);

        // Set up a signal handler to send a SigTerm (CTRL+C) emission when the process is terminated
        let signal_sender = sender.clone();
        let _ = ctrlc::set_handler(move || {
            signal_sender
                .send(Emission::SigTerm)
                .expect("failed to send sigterm")
        });
        
        // Earliest block height to start sync from
        let start_height = 0;
        let emitter_tip = wallet_tip.clone();
        let expected_mempool_txid = self.bdk_wallet
            .transactions()
            .filter(|tx| tx.chain_position.is_unconfirmed());
        // Create a new emitter that will emit the blocks and the mempool to the wallet thread
        let mut emitter = Emitter::new(self.rpc_client.clone(), emitter_tip, start_height, expected_mempool_txid);

        // Start the emitter thread that connects with the Bitcoin node and receives the blocks and the mempool
        spawn(move || -> Result<(), anyhow::Error> {
            // Send blocks one by one to the wallet thread, starting from last checkpoint or start_height
            while let Some(emission) = emitter.next_block()? {
                sender.send(Emission::Block(emission))?;
            }
            // Send the mempool to the wallet thread
            sender.send(Emission::Mempool(emitter.mempool()?))?;
            Ok(())
        });

        // Start the wallet thread that receives the blocks and the mempool from the emitter thread and applies them to the wallet
        for emission in receiver {
            match emission {
                // If the process is terminated(CTRL+C), exit the loop
                Emission::SigTerm => {
                    info!("Sigterm received, exiting...");
                    break;
                }
                // If a block is received, apply it to the wallet
                Emission::Block(block_emission) => {
                    let height = block_emission.block_height();
                    let hash = block_emission.block_hash();
                    let connected_to = block_emission.connected_to();
                    // Apply the block to the wallet
                    self.bdk_wallet.apply_block_connected_to(&block_emission.block, height, connected_to)?;
                    // Persist the wallet to the database
                    self.persist_wallet()?;
                    debug!(
                        "Applied block {} at height {}",
                        hash, height
                    );
                }
                Emission::Mempool(mempool_emission) => {
                    // Apply the mempool to the wallet
                    self.bdk_wallet.apply_evicted_txs(mempool_emission.evicted_ats());
                    self.bdk_wallet.apply_unconfirmed_txs(mempool_emission.new_txs);
                    // Persist the wallet to the database
                    self.persist_wallet()?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn db_path(public_key: String) -> String {
        format!("/tmp/regtest/wallet/{public_key}.db")
    }

    fn ensure_db_directory(db_path: &str) -> Result<(), anyhow::Error> {
        let path = Path::new(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn persist_wallet(&mut self) -> Result<(), anyhow::Error> {
        self.bdk_wallet.persist(&mut self.conn)?;
        Ok(())
    }

    /// Get or create a wallet with initial data read from rusqlite database.
    /// We use a single descriptor for the wallet, so we don't need to specify the change descriptor.
    /// see https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.create_single
    fn load_bdk_wallet(conn: &mut Connection, network: Network, wallet_config: &WalletConfig) -> Result<PersistedWallet<Connection>, anyhow::Error> {
        let private_key = wallet_config.funding_key.clone();

        // This descriptor for the wallet indicates native segwit (wpkh) public key for regtest network
        // See https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/macro.descriptor.html
        // and https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples
        let descriptor = format!("wpkh({})", private_key).to_string();
        
        // Load the wallet from the database
        let wallet_opt = BdkWallet::load()
            .descriptor(KeychainKind::External, Some(descriptor.to_string()))
            .check_network(network)
            .extract_keys()
            .load_wallet(conn)?;

        // If the wallet is not found, create a new one
        let wallet = match wallet_opt {
            Some(wallet) => wallet,
            None => BdkWallet::create_single(descriptor.to_string())
                .network(network)
                .create_wallet( conn)?,
        };

        Ok(wallet)
    }

    fn private_key_to_public_key(private_key: &String) -> Result<String, anyhow::Error> {
        let priv_key = PrivateKey::from_str(private_key)?;
        let public_key = priv_key.public_key(&Secp256k1::new());
        Ok(public_key.to_string())
    }
}

/// Extension trait for regtest-specific wallet functions
/// This trait provides utilities that are only available in regtest mode
#[cfg(any(test, feature = "example"))]
pub trait RegtestWallet {
    /// Check if the wallet is in regtest mode
    fn check_network(&self) -> Result<(), anyhow::Error>;

    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<Txid>, anyhow::Error>;
    
    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Txid>, anyhow::Error>;

    /// Fund the wallet with 50 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), anyhow::Error>;

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, address: &str, amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Send funds to a specific p2wpkh public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2wpkh(&mut self, public_key: &PublicKey, amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Send funds to a specific p2tr public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript], amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: WalletConfig) -> Result<(), anyhow::Error>;
}

#[cfg(any(test, feature = "example"))]
impl RegtestWallet for Wallet {

    fn check_network(&self) -> Result<(), anyhow::Error> {
        if self.network != Network::Regtest {
            use crate::errors::WalletError;

            return Err(WalletError::RegtestOnly.into());
        }
        Ok(())
    }

    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<Txid>, anyhow::Error> {
        self.check_network()?;

        let address = Address::from_str(address)?.assume_checked();
        let block_hashes = self.rpc_client.generate_to_address(num_blocks, &address)?;
        
        // Convert block hashes to transaction IDs (coinbase transactions)
        let mut coinbase_txids = Vec::new();
        for block_hash in block_hashes {
            let block = self.rpc_client.get_block(&block_hash)?;
            if let Some(coinbase_tx) = block.txdata.first() {
                coinbase_txids.push(coinbase_tx.compute_txid());
            }
        }
        
        Ok(coinbase_txids)
    }

    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Txid>, anyhow::Error> {
        self.check_network()?;
        // Use a different address for mining to avoid conflicts with the receive address
        let address = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";
        self.mine_to_address(num_blocks, address)
    }

    /// Fund the wallet with 50 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), anyhow::Error> {
        self.check_network()?;

        let address = self.receive_address()?;
        // Mine 1 block to the receive address
        self.mine_to_address(1, &address.to_string())?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(100)?;
        // Sync the wallet with the Bitcoin node to the latest block
        self.sync_wallet()?;

        Ok(())
    }

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, address: &str, amount: u64) -> Result<Transaction, anyhow::Error> {
        self.check_network()?;

        // Mine 1 block to the receive address
        let tx = self.send_to_address(address, amount, None)?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(1)?;
        // Sync the wallet with the Bitcoin node to the latest block
        self.sync_wallet()?;

        Ok(tx)
    }

    /// Send funds to a specific p2wpkh public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2wpkh(&mut self, public_key: &PublicKey, amount: u64) -> Result<Transaction, anyhow::Error> {
        let address = self.pub_key_to_p2wpk(public_key)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    fn fund_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript], amount: u64) -> Result<Transaction, anyhow::Error> {
        let address = self.pub_key_to_p2tr(x_public_key, tap_leaves)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    /// Clear the database
    fn clear_db(wallet_config: WalletConfig) -> Result<(), anyhow::Error> {
        let public_key = Self::private_key_to_public_key(&wallet_config.funding_key)?;
        let db_path = wallet_config.db_path.clone().unwrap_or_else(|| Self::db_path(public_key.to_string()));
        let _ = std::fs::remove_file(db_path);

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Ok, Result};
    use bitcoind::bitcoind::Bitcoind;
    use tracing_subscriber::EnvFilter;
    use std::{str::FromStr, sync::Once, time::Instant};
    use crate::config::Config;

    static INIT: Once = Once::new();

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

        Wallet::clear_db(config.wallet.clone())?;

        Ok(config)
    }


    #[test]
    #[ignore]
    fn test_bdk_wallet() -> Result<(), anyhow::Error> {
        // Arrenge
        let config = clean_and_load_config("config/regtest.yaml")?;

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
        );
        bitcoind.start()?;
        let start_load_wallet = Instant::now();

        let mut wallet = Wallet::new(config.bitcoin.clone(), config.wallet.clone())?;

        // Get a new address to receive bitcoin.
        let receive_address = wallet.receive_address()?;
        // Now it's safe to show the user their next address!
        println!("Your new bdk_wallet receive address is: {}", receive_address);

        // Check the balance of the wallet
        let balance = wallet.get_balance()?;
        println!("Wallet balance before syncing: {}", balance.total());
        
        // Send 300 BTC to the wallet using the RegtestWallet trait
        wallet.mine_to_address(6, &receive_address.to_string())?;
        let new_balance = wallet.get_balance()?;
        assert_eq!(new_balance.total(), balance.total(), "Balance should be the same until coinbase maturity");

        // Mine 100 blocks to ensure the coinbase output is mature
        wallet.mine(100)?;

        assert_eq!(new_balance.total(), balance.total(), "Balance should be the same until we sync the wallet");
        // Sync the wallet with the Bitcoin node to the latest block
        wallet.sync_wallet()?;

        let new_balance = wallet.get_balance()?;
        assert_eq!(new_balance.total(), balance.total() + Amount::from_sat(30_000_000_000), "Balance should have increased by 300 BTC after syncing the wallet");

        let wallet_tip_end = wallet.bdk_wallet.latest_checkpoint();
        println!(
            "Wallet fully loaded and synced in {}s",
            start_load_wallet.elapsed().as_secs_f32(),
        );
        println!(
            "Wallet tip is '{}:{}'",
            wallet_tip_end.height(),
            wallet_tip_end.hash()
        );

        println!(
            "Wallet has {} transactions and {:?} utxos",
            wallet.bdk_wallet.transactions().count(),
            wallet.bdk_wallet.list_unspent().count()
        );

        // Mine additional blocks to ensure coinbase maturity (100 confirmations required for coinbase)
        // The coinbase outputs from the 6 blocks we just mined need 100 confirmations
        wallet.mine(100)?;
        // Sync the wallet to the latest block to ensure the coinbase outputs are mature otherwise the transaction will fail
        wallet.sync_wallet()?;

        let balance = wallet.bdk_wallet.balance();
        assert_eq!(balance.total(), new_balance.total(), "Balance should be the same after syncing the wallet");

        // Build a transaction to send 50000 satoshis to a taproot address
        wallet.send_to_address("tb1pn3q7tv78u5sqyu6ngr7w82krtdfuf4a5tv3udkgy4ners2znxehsse5urx", 50_000, None)?;

        // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

        // Check the balance of the wallet
        let new_balance = wallet.bdk_wallet.balance();
        assert_eq!(new_balance.total(), balance.total() - Amount::from_sat(50_000) - Amount::from_sat(153), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

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
        
        // Mine 101 blocks to the receive address to ensure only one coinbase output is mature
        wallet.mine_to_address(101, &receive_address.to_string())?;
        

        // Sync the wallet with the Bitcoin node to the latest block
        wallet.sync_wallet()?;

        // Build a transaction to send 50000 satoshis to a taproot address
        // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
        let to_address = Address::from_str("tb1pn3q7tv78u5sqyu6ngr7w82krtdfuf4a5tv3udkgy4ners2znxehsse5urx")?.assume_checked();
        let mut psbt = {
            let mut builder = wallet.bdk_wallet.build_tx();
            builder
                .ordering(TxOrdering::Untouched)
                .add_recipient(to_address.script_pubkey(), Amount::from_sat(50_000));
            builder.finish()? //Returns a PartialSignedBitcoinTransaction https://docs.rs/bitcoin/0.32.6/bitcoin/psbt/struct.Psbt.html
        };
        // Sign the transaction
        // TODO: Use a custom signer using the key manager see
        // https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/signer/index.html
        let finalized = wallet.bdk_wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized, "we should have signed all the inputs");

        // Get the transaction from the psbt
        let tx = psbt.extract_tx().expect("tx");
        let balance = wallet.get_balance()?;
        // Broadcast the transaction
        wallet.send_transaction(&tx)?;

        // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

        // Check the balance of the wallet
        let new_balance = wallet.bdk_wallet.balance();
        assert_eq!(new_balance.total(), balance.total() - Amount::from_sat(50_000) - Amount::from_sat(153), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

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

        let balance = wallet.get_balance()?;
        let amount = Amount::from_sat(50_000);
        let address = Address::from_str("tb1pn3q7tv78u5sqyu6ngr7w82krtdfuf4a5tv3udkgy4ners2znxehsse5urx")?.assume_checked();

        let tx = wallet.fund_address(&address.to_string(), amount.to_sat())?;
        let new_balance = wallet.get_balance()?;
        assert_eq!(tx.output[0].value, amount, "Output should be 50000 satoshis");
        assert_eq!(tx.output[0].script_pubkey, address.script_pubkey(), "Output should be to the correct address");
        assert_eq!(new_balance.total(), balance.total() - amount - Amount::from_sat(153), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");
        
        let balance = new_balance;
        let public_key = PublicKey::from_str("020d4bf69a836ddb088b9492af9ce72b39de9ae663b41aa9699fef4278e5ff77b4")?;
        let address = wallet.pub_key_to_p2wpk(&public_key)?;
        println!("address: {:?}", address);
        // Send funds to a specific p2wpkh public key and mines 1 block
        let tx = wallet.fund_p2wpkh(&public_key, amount.to_sat())?;
        println!("p2wpkh tx: {:?}", tx);
        let new_balance = wallet.get_balance()?;
        assert_eq!(tx.output[0].value, amount, "Output should be 50000 satoshis");
        assert_eq!(tx.output[0].script_pubkey, ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?), "Output should be to the correct address");
        assert_eq!(new_balance.total(), balance.total() - amount - Amount::from_sat(141), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

        bitcoind.stop()?;
        Ok(())
    }
}
