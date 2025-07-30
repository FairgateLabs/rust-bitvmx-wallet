use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{secp256k1::Secp256k1, Address, Amount, Block, Network, PrivateKey, Transaction, Txid};

use tracing::{debug, info};

use bdk_wallet::{rusqlite::Connection, Balance, KeychainKind, PersistedWallet, SignOptions, Wallet as BdkWallet};
use ctrlc;
use bdk_bitcoind_rpc::{Emitter, bitcoincore_rpc::{Auth, Client, RpcApi},};
use std::{str::FromStr,sync::{mpsc::sync_channel, Arc}, thread::spawn};

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
    pub fn new(config: WalletConfig) -> Result<Wallet, anyhow::Error> {
        // Create a Bitcoin RPC client
        let bitcoin_config = config.bitcoin.clone();
        let rpc_client = Arc::new(Client::new(&bitcoin_config.url, Auth::UserPass(config.bitcoin.username.clone(), config.bitcoin.password.clone()))?);

        // Open or create a new sqlite database.
        let public_key = Self::private_key_to_public_key(&config.funding_key)?;
        let db_path = Self::get_db_path(public_key.to_string());
        let mut conn = Connection::open(db_path)?;

        let bdk_wallet = Self::get_bdk_wallet(&mut conn, config.bitcoin.network, &config.funding_key)?;

        Ok(Self {
            network: config.bitcoin.network,
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

    pub fn get_receive_address(&mut self) -> Result<Address, anyhow::Error> {
        let address_info = self.bdk_wallet.reveal_next_address(KeychainKind::External);
        // Mark previous address as used for receiving and persist to sqlite database.
        self.persist_wallet()?;
        Ok(address_info.address)
    }

    pub fn send_to_address(&mut self, amount: u64, address: &str) -> Result<Txid, anyhow::Error> {
        // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
        let to_address = Address::from_str(address)?.assume_checked();
        let mut psbt = {
            let mut builder = self.bdk_wallet.build_tx();
            builder
                .add_recipient(to_address.script_pubkey(), Amount::from_sat(amount));
            builder.finish()? //Returns a PartialSignedBitcoinTransaction https://docs.rs/bitcoin/0.32.6/bitcoin/psbt/struct.Psbt.html
        };
        // Sign the transaction
        let finalized = self.bdk_wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized, "we should have signed all the inputs");

        // Get the transaction from the psbt
        let tx = psbt.extract_tx().expect("tx");

        // Broadcast the transaction
        let tx_hash = self.send_transaction(&tx)?;
        Ok(tx_hash)
    }

    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<Txid, anyhow::Error> {
        let tx_hash = self.rpc_client.send_raw_transaction(tx)?;
        Ok(tx_hash)
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

    fn get_db_path(public_key: String) -> String {
        format!("/tmp/bdk_wallet_{public_key}.db")
    }

    fn persist_wallet(&mut self) -> Result<(), anyhow::Error> {
        self.bdk_wallet.persist(&mut self.conn)?;
        Ok(())
    }

    fn get_bdk_wallet(conn: &mut Connection, network: Network, private_key: &String) -> Result<PersistedWallet<Connection>, anyhow::Error> {
        // Get or create a wallet with initial data read from rusqlite database.
        // We use a single descriptor for the wallet, so we don't need to specify the change descriptor.
        // see https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.Wallet.html#method.create_single


        // This descriptor for the wallet indicates native segwit (wpkh) public key for regtest network
        // See https://docs.rs/bdk_wallet/1.2.0/bdk_wallet/macro.descriptor.html
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
#[cfg(any(test, feature = "regtest"))]
pub trait RegtestWallet {
    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<Txid>, anyhow::Error>;
    
    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Txid>, anyhow::Error>;

    /// Clear the database
    fn clear_db(public_key: String);
}

#[cfg(any(test, feature = "regtest"))]
impl RegtestWallet for Wallet {
    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<Txid>, anyhow::Error> {
        if self.network != Network::Regtest {
            return Err(WalletError::RegtestOnly.into());
        }

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
        // Use a different address for mining to avoid conflicts with the receive address
        let address = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";
        self.mine_to_address(num_blocks, address)
    }

    /// Clear the database
    fn clear_db(public_key: String) {
        let path = Wallet::get_db_path(public_key);
        let _ = std::fs::remove_file(path);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Ok, Result};
    use bitcoind::bitcoind::Bitcoind;
    use tracing_subscriber::EnvFilter;
    use std::{str::FromStr, time::Instant};

    fn config_trace() {
        let default_modules = ["info", "bitcoincore_rpc=off", "hyper=off","bollard=off"];

        let filter = EnvFilter::builder()
            .parse(default_modules.join(","))
            .expect("Invalid filter");

        tracing_subscriber::fmt()
            .with_target(true)
            .with_env_filter(filter)
            .init();
    }

    fn clean_and_load_config(config_path: &str) -> Result<WalletConfig, anyhow::Error> {
        config_trace();

        let config = bitvmx_settings::settings::load_config_file::<WalletConfig>(Some(
            config_path.to_string(),
        ))?;

        let public_key = Wallet::private_key_to_public_key(&config.funding_key)?;
        Wallet::clear_db(public_key);

        Ok(config)
    }


    #[test]
    fn test_bdk_wallet() -> Result<(), anyhow::Error> {
        // Arrenge
        let config = clean_and_load_config("config/regtest.yaml")?;
        let bitcoin_config = config.bitcoin.clone();

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            bitcoin_config.clone(),
        );
        bitcoind.start()?;
        let start_load_wallet = Instant::now();

        let mut wallet = Wallet::new(config)?;

        // Get a new address to receive bitcoin.
        let receive_address = wallet.get_receive_address()?;
        // Now it's safe to show the user their next address!
        println!("Your new bdk_wallet receive address is: {}", receive_address);

        // Check the balance of the wallet
        let balance = wallet.get_balance()?;
        println!("Wallet balance before syncing: {}", balance.total());
        
        // Send 300 BTC to the wallet using the RegtestWallet trait
        wallet.mine_to_address(6, &receive_address.to_string())?;
        let new_balance = wallet.get_balance()?;
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

        // Build a transaction to send 50000 satoshis to a taproot address
        wallet.send_to_address(50_000, "tb1pn3q7tv78u5sqyu6ngr7w82krtdfuf4a5tv3udkgy4ners2znxehsse5urx")?;

        // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

        let balance = wallet.bdk_wallet.balance();
        assert_eq!(balance.total(), new_balance.total(), "Balance should be the same after sending the transaction before syncing");

        // Sync the wallet with the Bitcoin node to the latest block
        wallet.sync_wallet()?;

        // Check the balance of the wallet
        let new_balance = wallet.bdk_wallet.balance();
        assert_eq!(new_balance.total(), balance.total() - Amount::from_sat(50_000) - Amount::from_sat(153), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

        bitcoind.stop()?;
        Ok(())
    }

    #[test]
    fn test_bdk_wallet_build_tx() -> Result<(), anyhow::Error> {
        // Arrenge
        let config = clean_and_load_config("config/regtest.yaml")?;
        let bitcoin_config = config.bitcoin.clone();

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            bitcoin_config.clone(),
        );
        bitcoind.start()?;

        let mut wallet = Wallet::new(config)?;

        // Get a new address to receive bitcoin.
        let receive_address = wallet.get_receive_address()?;
        
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
        // Broadcast the transaction
        wallet.send_transaction(&tx)?;

        // If needed it can be speeded up https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.build_fee_bump

        let balance = wallet.bdk_wallet.balance();

        // Sync the wallet with the Bitcoin node to the latest block
        wallet.sync_wallet()?;

        // Check the balance of the wallet
        let new_balance = wallet.bdk_wallet.balance();
        assert_eq!(new_balance.total(), balance.total() - Amount::from_sat(50_000) - Amount::from_sat(153), "Balance should have decreased by 50000 satoshis and fees after syncing the wallet");

        bitcoind.stop()?;
        Ok(())
    }
}
