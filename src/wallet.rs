#[allow(unused_imports)]
use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{
    Address, Amount, Block, FeeRate, Network, PrivateKey, Psbt, PublicKey, ScriptBuf, Transaction,
    Txid, XOnlyPublicKey,
};

use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::key_manager::KeyManager;
use protocol_builder::scripts::{self, ProtocolScript};
use tracing::{debug, error, info};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client, RpcApi}, BlockEvent, Emitter, MempoolEvent
};
use bdk_wallet::{
    coin_selection::DefaultCoinSelectionAlgorithm, rusqlite::Connection,
    wallet_name_from_descriptor, Balance, KeychainKind, LocalOutput, PersistedWallet, SignOptions,
    TxBuilder, TxOrdering, Wallet as BdkWallet, WalletTx,
};
use ctrlc;
use std::{
    fmt::{self, Display},
    fs,
    path::Path,
    rc::Rc,
    str::FromStr,
    sync::{mpsc::sync_channel, Arc},
    thread::spawn, time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub enum Emission {
    SigTerm,
    Block(bdk_bitcoind_rpc::BlockEvent<Block>),
    Mempool(bdk_bitcoind_rpc::MempoolEvent),
}

pub struct Wallet {
    pub network: bitcoin::Network,
    pub rpc_client: Arc<Client>,
    pub bdk_wallet: PersistedWallet<Connection>,
    pub public_key: PublicKey,
    pub name: String,
    pub start_height: u32,
    pub is_ready: bool,
    conn: Connection,
    key_manager: Rc<KeyManager>,
}

impl Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Wallet {
    /// Create a wallet from a public key used to get the private key from the key manager
    pub fn from_key_manager(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        public_key: &PublicKey,
        change_public_key: Option<&PublicKey>,
    ) -> Result<Wallet, WalletError> {
        let descriptor = Self::p2wpkh_descriptor(&key_manager, public_key)?;
        let change_descriptor = match change_public_key {
            Some(change_public_key) => {
                Some(Self::p2wpkh_descriptor(&key_manager, change_public_key)?)
            }
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            key_manager,
            public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Create a wallet from an index to derive the key pair from the key manager
    pub fn from_derive_keypair(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        index: u32,
        change_index: Option<u32>,
    ) -> Result<Wallet, WalletError> {
        let public_key = key_manager.derive_keypair(index)?;
        let descriptor = Self::p2wpkh_descriptor(&key_manager, &public_key)?;
        let change_descriptor = match change_index {
            Some(change_index) => {
                let change_public_key = key_manager.derive_keypair(change_index)?;
                Some(Self::p2wpkh_descriptor(&key_manager, &change_public_key)?)
            }
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            key_manager,
            &public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Create a wallet from a private key, stores it in the key manager
    pub fn from_private_key(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        private_key: &str,
        change_private_key: Option<&str>,
    ) -> Result<Wallet, WalletError> {
        let public_key = key_manager.import_private_key(private_key)?;
        let descriptor = Self::p2wpkh_descriptor(&key_manager, &public_key)?;
        let change_descriptor = match change_private_key {
            Some(change_private_key) => {
                let change_public_key = key_manager.import_private_key(change_private_key)?;
                Some(Self::p2wpkh_descriptor(&key_manager, &change_public_key)?)
            }
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            key_manager,
            &public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

     /// Create a wallet from a config file
     pub fn from_config(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
    ) -> Result<Wallet, WalletError> {
        let receive_key = match wallet_config.receive_key.clone() {
            Some(receive_key) => receive_key,
            None => return Err(WalletError::InvalidReceiveKey("No receive key provided in config file".to_string())),
        };
        let public_key = key_manager.import_private_key(&receive_key)?;
        let descriptor = Self::p2wpkh_descriptor(&key_manager, &public_key)?;
        let change_descriptor = match wallet_config.change_key.clone() {
            Some(change_key) => {
                let change_public_key = key_manager.import_private_key(&change_key)?;
                Some(Self::p2wpkh_descriptor(&key_manager, &change_public_key)?)
            }
            None => None,
        };
        Self::new(
            bitcoin_config,
            wallet_config,
            key_manager,
            &public_key,
            &descriptor,
            change_descriptor.as_deref(),
        )
    }

    /// Create a p2wpkh descriptor using a key from the key manager
    fn p2wpkh_descriptor(
        key_manager: &Rc<KeyManager>,
        public_key: &PublicKey,
    ) -> Result<String, WalletError> {
        // Export the private key from the key manager
        let private_key = key_manager.export_secret(public_key)?;
        // This descriptor for the wallet, wpkh indicates native segwit private key
        // See https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/macro.descriptor.html
        // and https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples
        Ok(format!("wpkh({})", private_key.to_wif()))
    }

    /// Create a wallet from partial private keys of musig2
    pub fn from_partial_keys(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        partial_private_keys: Vec<String>,
        key_manager: Rc<KeyManager>,
    ) -> Result<Wallet, WalletError> {
        if partial_private_keys.is_empty() {
            error!("No partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys);
        }
        let aggregated_public_key = if partial_private_keys.iter().all(|key| key.len() == 64) {
            key_manager.import_partial_secret_keys(partial_private_keys, bitcoin_config.network)?
        } else if partial_private_keys.iter().all(|key| key.len() == 52) {
            key_manager.import_partial_private_keys(partial_private_keys, bitcoin_config.network)?
        } else {
            error!("Invalid partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys);
        };

        let descriptor = Self::p2tr_descriptor(&key_manager, &aggregated_public_key)?;
        Self::new(
            bitcoin_config,
            wallet_config,
            key_manager,
            &aggregated_public_key,
            &descriptor,
            None,
        )
    }

    /// Create a p2wpkh descriptor using a key from the key manager
    fn p2tr_descriptor(
        key_manager: &Rc<KeyManager>,
        public_key: &PublicKey,
    ) -> Result<String, WalletError> {
        // Export the private key from the key manager
        let private_key = key_manager.export_secret(public_key)?;
        // P2TR output with the specified key as internal key, and optionally a tree of script paths.
        // tr(KEY) or tr(KEY,TREE) (top level only): P2TR output with the specified key as internal key, and optionally a tree of script paths.
        // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples
        Ok(format!("tr({})", private_key.to_wif()))
    }

    /// Returns a wallet with initial data persisted to a rusqlite database.
    /// Note that the descriptor secret keys are not persisted to the database.
    pub fn new(
        bitcoin_config: RpcConfig,
        wallet_config: WalletConfig,
        key_manager: Rc<KeyManager>,
        public_key: &PublicKey,
        descriptor: &str,
        change_descriptor: Option<&str>
    ) -> Result<Wallet, WalletError> {
        // Create a Bitcoin RPC client
        let rpc_client = Arc::new(Client::new(
            &bitcoin_config.url,
            Auth::UserPass(
                bitcoin_config.username.clone(),
                bitcoin_config.password.clone(),
            ),
        )?);
        let start_height = wallet_config.start_height.unwrap_or(0);
        // Wallet config
        let db_path = wallet_config.db_path.clone();
        // Ensure the directory exists
        Self::ensure_db_directory(&db_path)?;
        // Open or create a new sqlite database.
        let mut conn = Connection::open(db_path)?;

        // Get or create a wallet with initial data read from rusqlite database.
        let bdk_wallet = Self::init_bdk_wallet(
            &mut conn,
            bitcoin_config.network,
            descriptor,
            change_descriptor,
        )?;

        let name = wallet_name_from_descriptor(
            descriptor,
            change_descriptor,
            bitcoin_config.network,
            bdk_wallet.secp_ctx(),
        )?;

        Ok(Self {
            network: bitcoin_config.network,
            rpc_client,
            bdk_wallet,
            name,
            public_key: *public_key,
            start_height,
            is_ready: false,
            conn,
            key_manager,
        })
    }

    /// Load or create a wallet with initial data and persist it to the rusqlite database.
    /// Note that the descriptor secret keys are not persisted to the database.
    fn init_bdk_wallet(
        conn: &mut Connection,
        network: Network,
        descriptor: &str,
        change_descriptor: Option<&str>,
    ) -> Result<PersistedWallet<Connection>, WalletError> {
        // Load the wallet from the database
        let mut load_params =
            BdkWallet::load().descriptor(KeychainKind::External, Some(descriptor.to_string()));
        if let Some(chd) = change_descriptor {
            load_params = load_params.descriptor(KeychainKind::Internal, Some(chd.to_string()));
        }
        let wallet_opt = load_params
            .check_network(network)
            .extract_keys()
            .load_wallet(conn)
            .map_err(|e| WalletError::LoadWalletWithPersistError(Box::new(e)))?;

        let mut wallet = match wallet_opt {
            Some(_wallet) => _wallet,
            // If the wallet is not found, create a new one
            None => match change_descriptor {
                Some(change) => BdkWallet::create(descriptor.to_string(), change.to_string())
                    .network(network)
                    .create_wallet(conn)
                    .map_err(|e| WalletError::CreateWalletError(Box::new(e)))?,
                // If no change descriptor is provided, create a single descriptor wallet
                // see https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.Wallet.html#method.create_single
                None => BdkWallet::create_single(descriptor.to_string())
                    .network(network)
                    .create_wallet(conn)
                    .map_err(|e| WalletError::CreateWalletError(Box::new(e)))?,
            },
        };

        // Persist the wallet to the database
        wallet.persist(conn)?;
        Ok(wallet)
    }

    pub fn balance(&self) -> Balance {
        self.bdk_wallet.balance()
    }

    pub fn receive_address(&mut self) -> Result<Address, WalletError> {
        let address_info = self.bdk_wallet.reveal_next_address(KeychainKind::External);
        // Mark previous address as used for receiving and persist to sqlite database.
        self.persist_wallet()?;
        Ok(address_info.address)
    }

    pub fn send_to_address_tx(
        &mut self,
        to_address: &str,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
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
        // Persist the wallet to the database to avoid change address reuse
        self.persist_wallet()?;
        // Get the transaction from the psbt
        let tx = psbt.extract_tx().expect("tx");
        Ok(tx)
    }

    pub fn send_to_address(
        &mut self,
        to_address: &str,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        let tx = self.send_to_address_tx(to_address, amount, fee_rate)?;
        // Broadcast the transaction and update the wallet with the unconfirmed transaction
        self.send_transaction(&tx)?;
        Ok(tx)
    }

    pub fn pub_key_to_p2wpk(
        public_key: &PublicKey,
        network: Network,
    ) -> Result<Address, WalletError> {
        let script = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);
        let address = Address::from_script(&script, network)?;
        Ok(address)
    }

    pub fn send_to_p2wpkh(
        &mut self,
        public_key: &PublicKey,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        let address = Wallet::pub_key_to_p2wpk(public_key, self.network)?;
        let tx = self.send_to_address(&address.to_string(), amount, fee_rate)?;
        Ok(tx)
    }

    pub fn pub_key_to_p2tr(
        &mut self,
        x_public_key: &XOnlyPublicKey,
        tap_leaves: &[ProtocolScript],
    ) -> Result<Address, WalletError> {
        let tap_spend_info = scripts::build_taproot_spend_info(
            self.bdk_wallet.secp_ctx(),
            x_public_key,
            tap_leaves,
        )?;
        let script = ScriptBuf::new_p2tr_tweaked(tap_spend_info.output_key());
        let address = Address::from_script(&script, self.network)?;
        Ok(address)
    }

    pub fn send_to_p2tr(
        &mut self,
        x_public_key: &XOnlyPublicKey,
        tap_leaves: &[ProtocolScript],
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, WalletError> {
        let address = self.pub_key_to_p2tr(x_public_key, tap_leaves)?;
        let tx = self.send_to_address(&address.to_string(), amount, fee_rate)?;
        Ok(tx)
    }

    /// Send a transaction and update the wallet with the unconfirmed transaction
    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<Txid, WalletError> {
        let tx_hash = self.rpc_client.send_raw_transaction(tx)?;
        // Sync the wallet to update transactions in the mempool
        let last_seen_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.bdk_wallet.apply_unconfirmed_txs(vec![(tx.clone(), last_seen_timestamp)]);
        Ok(tx_hash)
    }

    pub fn get_wallet_tx(&self, txid: Txid) -> Result<Option<WalletTx>, WalletError> {
        let tx = self.bdk_wallet.get_tx(txid);
        Ok(tx)
    }

    pub fn list_unspent(&self) -> Result<Vec<LocalOutput>, WalletError> {
        let unspent = self.bdk_wallet.list_unspent().collect::<Vec<_>>();
        Ok(unspent)
    }

    pub fn cancel_tx(&mut self, tx: &Transaction) -> Result<(), WalletError> {
        self.bdk_wallet.cancel_tx(tx);
        Ok(())
    }

    pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
        self.bdk_wallet.build_tx()
    }

    pub fn sign(
        &mut self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> Result<bool, WalletError> {
        let finalized = self.bdk_wallet.sign(psbt, sign_options)?;
        Ok(finalized)
    }

    pub fn tick(&mut self) -> Result<u64, WalletError> {
        let mut blocks_received = 0_u64;
        let mut emitter = self.create_emitter();
        if let Some(emission) = emitter.next_block()? {
            // There is a new block to sync
            self.sync_block(emission)?;
            blocks_received += 1;
        } else {
            // There is no new block to sync, so we sync the mempool
            self.sync_mempool(emitter.mempool()?)?;
            // The wallet is ready to be used
            self.is_ready = true;
        }
        Ok(blocks_received)
   }

    pub fn sync_block(&mut self, block_emission: BlockEvent<Block>) -> Result<(), WalletError> {
        let height = block_emission.block_height();
        let connected_to = block_emission.connected_to();
        self.bdk_wallet.apply_block_connected_to(&block_emission.block, height, connected_to)?;
        self.persist_wallet()?;
        debug!("Applied block {} at height {}", block_emission.block_hash(), height);
        Ok(())  
    }

    pub fn sync_mempool(&mut self, mempool_emission: MempoolEvent) -> Result<(), WalletError> {
        self.bdk_wallet.apply_evicted_txs(mempool_emission.evicted);
        self.bdk_wallet.apply_unconfirmed_txs(mempool_emission.update);
        self.persist_wallet()?;
        debug!("Applied evicted and unconfirmed transactions");
        Ok(())  
    }

    pub fn sync_wallet(&mut self) -> Result<u64, WalletError> {
        info!("Syncing wallet ...");
        let start_sync = Instant::now();
        let mut emitter = self.create_emitter();
        let mut blocks_received = 0_u64;
        while let Some(emission) = emitter.next_block()? {
            blocks_received += 1;
            self.sync_block(emission)?;
        }
        self.sync_mempool(emitter.mempool()?)?;
        info!(
            "Synced wallet: {} blocks and mempool in {}s",
            blocks_received,
            start_sync.elapsed().as_secs_f32(),
        );
        self.is_ready = true;
        Ok(blocks_received)
    }

    pub fn sync_wallet_multi_thread(&mut self) -> Result<u64, WalletError> {
        let start_sync = Instant::now();
        info!("Syncing wallet with multi thread ...");
        let (sender, receiver) = sync_channel::<Emission>(21);

        let signal_sender = sender.clone();
        let _ = ctrlc::set_handler(move || {
            signal_sender
                .send(Emission::SigTerm)
                .expect("Sync wallet error: failed to send SIGTERM")
        });

        let mut emitter = self.create_emitter();
        let emitter_handle = spawn(move || -> Result<(), WalletError> {
            while let Some(emission) = emitter.next_block()? {
                sender.send(Emission::Block(emission))?;
            }
            sender.send(Emission::Mempool(emitter.mempool()?))?;
            Ok(())
        });
 
        let mut blocks_received = 0_u64;
        for emission in receiver {
            match emission {
                Emission::SigTerm => {
                    info!("SIGTERM received, exiting...");
                    break;
                }
                Emission::Block(block_emission) => {
                    blocks_received += 1;
                    self.sync_block(block_emission)?;
                }
                Emission::Mempool(event) => {
                    self.sync_mempool(event)?;
                    break;
                }
            }
        }
        match emitter_handle.join() {
            Ok(_) => {
                info!(
                    "Synced wallet with multi thread: {} blocks and mempool in {}s",
                    blocks_received,
                    start_sync.elapsed().as_secs_f32(),
                );
                self.is_ready = true;
                Ok(blocks_received)
            },
            Err(e) => { 
                Err(WalletError::ThreadPanicked(format!("Sync wallet error: Emitter thread panicked with: {e:?}")))
            }
        }
    }

    fn create_emitter(&self) -> Emitter<Arc<Client>> {
        // Obtain latest checkpoint (last synced block height and hash)
        let wallet_tip = self.bdk_wallet.latest_checkpoint();
        let wallet_unconfirmed_txs = self.bdk_wallet
            .transactions()
            .filter(|tx| tx.chain_position.is_unconfirmed());
        Emitter::new(
            self.rpc_client.clone(),
            wallet_tip,
            self.start_height,
            wallet_unconfirmed_txs,
        )
    }

    fn ensure_db_directory(db_path: &str) -> Result<(), WalletError> {
        let path = Path::new(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn persist_wallet(&mut self) -> Result<(), WalletError> {
        self.bdk_wallet.persist(&mut self.conn)?;
        Ok(())
    }
}

/// Extension trait for regtest-specific wallet functions
/// This trait provides utilities that are only available in regtest mode
pub trait RegtestWallet {
    /// Check if the wallet is in regtest mode
    fn check_network(&self) -> Result<(), WalletError>;

    /// Export the wallet
    fn export_wallet(&self) -> Result<(PublicKey, PrivateKey), WalletError>;

    /// Generate blocks and send the coinbase reward to a specific address
    /// Returns the coinbase transactions
    /// This function is only available in regtest mode
    fn mine_to_address(
        &self,
        num_blocks: u64,
        address: &str,
    ) -> Result<Vec<Transaction>, WalletError>;

    /// Generate a specified number of blocks to a default address
    /// Returns the coinbase transactions
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Transaction>, WalletError>;

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), WalletError>;

    /// Send funds to a specific address and mines 1 block
    /// This function is only available in regtest mode
    fn fund_address(&mut self, to_address: &str, amount: u64)
        -> Result<Transaction, WalletError>;

    /// Send funds to a specific p2wpkh public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2wpkh(
        &mut self,
        public_key: &PublicKey,
        amount: u64,
    ) -> Result<Transaction, WalletError>;

    /// Send funds to a specific p2tr public key and mines 1 block
    /// This function is only available in regtest mode
    fn fund_p2tr(
        &mut self,
        x_public_key: &XOnlyPublicKey,
        tap_leaves: &[ProtocolScript],
        amount: u64,
    ) -> Result<Transaction, WalletError>;

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), WalletError>;
}

impl RegtestWallet for Wallet {
    fn check_network(&self) -> Result<(), WalletError> {
        if self.network != Network::Regtest {
            use crate::errors::WalletError;

            return Err(WalletError::RegtestOnly);
        }
        Ok(())
    }

    fn export_wallet(&self) -> Result<(PublicKey, PrivateKey), WalletError> {
        let private_key = self.key_manager.export_secret(&self.public_key)?;
        Ok((self.public_key, private_key))
    }

    /// Generate blocks and send the coinbase reward to a specific address
    /// This function is only available in regtest mode
    fn mine_to_address(
        &self,
        num_blocks: u64,
        address: &str,
    ) -> Result<Vec<Transaction>, WalletError> {
        self.check_network()?;

        let address = Address::from_str(address)?.require_network(self.network)?;
        let block_hashes = self.rpc_client.generate_to_address(num_blocks, &address)?;

        // Convert block hashes to coinbase transactions
        let mut coinbase_txs = Vec::new();
        for block_hash in block_hashes {
            let block = self.rpc_client.get_block(&block_hash)?;
            if let Some(coinbase_tx) = block.txdata.first() {
                coinbase_txs.push(coinbase_tx.clone());
            }
        }

        Ok(coinbase_txs)
    }

    /// Generate a specified number of blocks to a default address
    /// This function is only available in regtest mode
    fn mine(&self, num_blocks: u64) -> Result<Vec<Transaction>, WalletError> {
        self.check_network()?;
        // Use a different address for mining to avoid conflicts with the receive address
        let address = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";
        self.mine_to_address(num_blocks, address)
    }

    /// Fund the wallet with 150 BTC
    /// This function is only available in regtest mode
    fn fund(&mut self) -> Result<(), WalletError> {
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
    fn fund_address(
        &mut self,
        to_address: &str,
        amount: u64,
    ) -> Result<Transaction, WalletError> {
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
    fn fund_p2wpkh(
        &mut self,
        public_key: &PublicKey,
        amount: u64,
    ) -> Result<Transaction, WalletError> {
        let address = Wallet::pub_key_to_p2wpk(public_key, self.network)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    fn fund_p2tr(
        &mut self,
        x_public_key: &XOnlyPublicKey,
        tap_leaves: &[ProtocolScript],
        amount: u64,
    ) -> Result<Transaction, WalletError> {
        let address = self.pub_key_to_p2tr(x_public_key, tap_leaves)?;
        let tx = self.fund_address(&address.to_string(), amount)?;
        Ok(tx)
    }

    /// Clear the database
    /// This function is only available in regtest mode
    fn clear_db(wallet_config: &WalletConfig) -> Result<(), WalletError> {
        let db_path = Path::new(&wallet_config.db_path);
        info!("Clearing db at {}", db_path.display());
        if db_path.exists() {
            std::fs::remove_file(db_path)?;
        }

        Ok(())
    }
}
