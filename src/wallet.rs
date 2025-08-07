#[allow(unused_imports)]
use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{secp256k1::Secp256k1, Address, Amount, Block, FeeRate, Network, PrivateKey, Psbt, PublicKey, ScriptBuf, Transaction, Txid, XOnlyPublicKey};

use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use protocol_builder::scripts::{self, ProtocolScript};
use tracing::{debug, error, info};

use bdk_wallet::{coin_selection::DefaultCoinSelectionAlgorithm, rusqlite::Connection, Balance, KeychainKind, LocalOutput, PersistedWallet, SignOptions, TxBuilder, TxOrdering, Wallet as BdkWallet, WalletTx};
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
    pub bdk_wallet: PersistedWallet<Connection>,
    pub public_key: String,
    pub start_height: u32,
    conn: Connection,
}
enum StoreKey {
    CreateWalletIndex,
    Wallet(String),
    Funding(String, String),
    PendingTransfer(String, String),
}

impl StoreKey {
    pub fn get_key(&self) -> String {
        let base = "wallet";
        match self {
            Self::Wallet(identifier) => format!("{base}/name/{identifier}"),
            Self::Funding(identifier, funding_id) => {
                format!("{base}/{identifier}/funding/{funding_id}")
            }
            Self::PendingTransfer(identifier, funding_id) => {
                format!("{base}/{identifier}/transfers/{funding_id}")
            }
            Self::CreateWalletIndex => format!("{base}/index"),
        }
    }
}

impl Wallet {
    pub fn new(bitcoin_config: RpcConfig, wallet_config: WalletConfig) -> Result<Wallet, anyhow::Error> {
        // Create a Bitcoin RPC client
        let rpc_client = Arc::new(Client::new(&bitcoin_config.url, Auth::UserPass(bitcoin_config.username.clone(), bitcoin_config.password.clone()))?);
        let start_height = wallet_config.start_height.unwrap_or(0);
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
            bdk_wallet,
            public_key: public_key.to_string(),
            start_height,
            conn,
        })
    }

    pub fn balance(&self) -> Balance {
       self.bdk_wallet.balance()
    }

    pub fn receive_address(&mut self) -> Result<Address, anyhow::Error> {
        let address_info = self.bdk_wallet.reveal_next_address(KeychainKind::External);
        // Mark previous address as used for receiving and persist to sqlite database.
        self.persist_wallet()?;
        Ok(address_info.address)
    }

    pub fn send_to_address_tx(&mut self, to_address: &str, amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
         // convert to address
         let to_address = Address::from_str(to_address)?.require_network(self.network)?;
         // See https://docs.rs/bdk_wallet/latest/bdk_wallet/struct.TxBuilder.html
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
        Ok(tx)
    }

    pub fn send_to_address(&mut self, to_address: &str, amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
        let tx = self.send_to_address_tx(to_address, amount, fee_rate)?;
        // Broadcast the transaction
        self.send_transaction(&tx)?;
        // Sync the wallet to update transactions in the mempool
        self.sync_wallet()?;
        Ok(tx)
    }

    pub fn pub_key_to_p2wpk(public_key: &PublicKey, network: Network) -> Result<Address, anyhow::Error> {
        let script = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);
        let address = Address::from_script(&script, network)?;
        Ok(address)
    }

    pub fn send_to_p2wpkh(&mut self, public_key: &PublicKey, amount: u64, fee_rate: Option<u64>) -> Result<Transaction, anyhow::Error> {
        let address = Wallet::pub_key_to_p2wpk(public_key, self.network)?;
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
        Ok(tx_hash)
    }

    pub fn get_wallet_tx(&self, txid: Txid) -> Result<Option<WalletTx>, anyhow::Error> {
        let tx = self.bdk_wallet.get_tx(txid);
        Ok(tx)
    }

    pub fn list_unspent(&self) -> Result<Vec<LocalOutput>, anyhow::Error> {
        let unspent = self.bdk_wallet.list_unspent().collect::<Vec<_>>();
        Ok(unspent)
    }

    pub fn cancel_tx(&mut self, tx: &Transaction) -> Result<(), anyhow::Error> {
        self.bdk_wallet.cancel_tx(tx);
        Ok(())
    }

    pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
        self.bdk_wallet.build_tx()
    }

    pub fn sign(&mut self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<bool, anyhow::Error> {
        let finalized = self.bdk_wallet.sign(psbt, sign_options)?;
        Ok(finalized)
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
        let emitter_tip = wallet_tip.clone();
        let expected_mempool_txid = self.bdk_wallet
            .transactions()
            .filter(|tx| tx.chain_position.is_unconfirmed());
        // Create a new emitter that will emit the blocks and the mempool to the wallet thread
        let mut emitter = Emitter::new(self.rpc_client.clone(), emitter_tip, self.start_height, expected_mempool_txid);

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

    // pub fn import_partial_private_keys(
    //     &self,
    //     identifier: &str,
    //     partial_keys: Vec<String>,
    //     network: bitcoin::Network,
    // ) -> Result<(), WalletError> {
    //     if partial_keys.is_empty() {
    //         error!("No partial private keys provided");
    //         return Err(WalletError::InvalidPartialPrivateKeys);
    //     }

    //     let aggregated_public_key = if partial_keys.iter().all(|key| key.len() == 64) {
    //         self.key_manager
    //             .import_partial_secret_keys(partial_keys, network)?
    //     } else if partial_keys.iter().all(|key| key.len() == 52) {
    //         self.key_manager
    //             .import_partial_private_keys(partial_keys, network)?
    //     } else {
    //         error!("Invalid partial private keys provided");
    //         return Err(WalletError::InvalidPartialPrivateKeys);
    //     };

    //     let key = StoreKey::Wallet(identifier.to_string()).get_key();

    //     if self.store.has_key(&key)? {
    //         return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
    //     }

    //     self.store.set(key, aggregated_public_key, None)?;

    //     Ok(())
    // }

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
pub trait RegtestWallet {
    /// Check if the wallet is in regtest mode
    fn check_network(&self) -> Result<(), anyhow::Error>;

    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<Txid>, anyhow::Error>;
    
    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Txid>, anyhow::Error>;

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), anyhow::Error>;

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, to_address: &str, amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Send funds to a specific p2wpkh public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2wpkh(&mut self, public_key: &PublicKey, amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Send funds to a specific p2tr public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript], amount: u64) -> Result<Transaction, anyhow::Error>;

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), anyhow::Error>;
}

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

        let address = Address::from_str(address)?.require_network(self.network)?;
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

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), anyhow::Error> {
        self.check_network()?;

        let address = self.receive_address()?;
        // Mine 1 block to the receive address to get 50 BTC
        self.mine_to_address(3, &address.to_string())?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(100)?;
        // Sync the wallet with the Bitcoin node to the latest block and mempool
        self.sync_wallet()?;

        Ok(())
    }

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, to_address: &str, amount: u64) -> Result<Transaction, anyhow::Error> {
        self.check_network()?;

        // Mine 1 block to the receive address
        let tx = self.send_to_address(to_address, amount, None)?;
        // Mine 100 blocks to ensure the coinbase output is mature
        self.mine(1)?;
        // Sync the wallet with the Bitcoin node to the latest block and mempool
        self.sync_wallet()?;

        Ok(tx)
    }

    /// Send funds to a specific p2wpkh public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2wpkh(&mut self, public_key: &PublicKey, amount: u64) -> Result<Transaction, anyhow::Error> {
        let address = Wallet::pub_key_to_p2wpk(public_key, self.network)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    fn fund_p2tr(&mut self, x_public_key: &XOnlyPublicKey, tap_leaves: &[ProtocolScript], amount: u64) -> Result<Transaction, anyhow::Error> {
        let address = self.pub_key_to_p2tr(x_public_key, tap_leaves)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    /// Clear the database
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), anyhow::Error> {
        let public_key = Self::private_key_to_public_key(&wallet_config.funding_key)?;
        let db_path = wallet_config.db_path.clone().unwrap_or_else(|| Self::db_path(public_key.to_string()));
        let _ = std::fs::remove_file(db_path);

        Ok(())
    }
}