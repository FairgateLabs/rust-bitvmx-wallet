use crate::{
    config::Config,
    errors::WalletError,
    wallet::{RegtestWallet, Wallet},
};
use bitcoin::PublicKey;
use key_manager::{create_key_manager_from_config, key_manager::KeyManager, key_store::KeyStore};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{error, info};

enum StoreKey {
    CreateWalletIndex,
    Wallet(String),
}

impl StoreKey {
    pub fn get_key(&self) -> String {
        let base = "wallet";
        match self {
            Self::Wallet(identifier) => format!("{base}/name/{identifier}"),
            Self::CreateWalletIndex => format!("{base}/index"),
        }
    }
    pub fn db_path(&self) -> String {
        format!("/tmp/wallet_manager/{}.db", self.get_key())
    }
}

pub struct WalletManager {
    pub config: Config,
    pub key_manager: Rc<KeyManager>,
    pub store: Rc<Storage>,
}

/// Manage multiple wallets in a single instance, used for testing purposes
impl WalletManager {
    pub fn new(config: Config) -> Result<WalletManager, anyhow::Error> {
        let storage: Rc<Storage> = Rc::new(Storage::new(&config.storage)?);
        let key_store = KeyStore::new(storage.clone());
        let key_manager = Rc::new(create_key_manager_from_config(
            &config.key_manager,
            key_store,
            storage.clone(),
        )?);
        Ok(Self {
            config,
            key_manager,
            store: storage,
        })
    }

    pub fn list_wallets(&self) -> Result<Vec<(String, PublicKey)>, WalletError> {
        let key = StoreKey::Wallet(String::new()).get_key();
        let mut wallets = Vec::new();

        for identifier_key in self.store.partial_compare_keys(&key)? {
            let identifier = identifier_key.strip_prefix(&key).unwrap().to_string();
            let pubkey: PublicKey = self
                .store
                .get(&identifier_key)?
                .ok_or(WalletError::KeyNotFound(identifier_key))?;

            wallets.push((identifier, pubkey));
        }

        Ok(wallets)
    }

    pub fn create_new_wallet(&self, identifier: &str) -> Result<Wallet, anyhow::Error> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()).into());
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let index = self.get_wallet_index()?;
        let wallet = Wallet::from_derive_keypair(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            index,
            None,
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    pub fn create_wallet_from_derive_keypair(
        &self,
        identifier: &str,
        index: u32,
    ) -> Result<Wallet, anyhow::Error> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()).into());
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_derive_keypair(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            index,
            None,
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    pub fn create_wallet_from_private_key(
        &self,
        identifier: &str,
        private_key: &str,
    ) -> Result<Wallet, anyhow::Error> {
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()).into());
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_private_key(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            private_key,
            None,
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    pub fn create_wallet_from_partial_keys(
        &self,
        identifier: &str,
        partial_keys: Vec<String>,
    ) -> Result<Wallet, anyhow::Error> {
        if partial_keys.is_empty() {
            error!("No partial private keys provided");
            return Err(WalletError::InvalidPartialPrivateKeys.into());
        }

        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()).into());
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        let wallet = Wallet::from_partial_keys(
            self.config.bitcoin.clone(),
            config_wallet,
            partial_keys,
            self.key_manager.clone(),
        )?;

        self.store.set(key, wallet.public_key, None)?;

        Ok(wallet)
    }

    pub fn load_wallet(&self, identifier: &str) -> Result<Wallet, anyhow::Error> {
        if identifier.trim().is_empty() {
            return Err(
                WalletError::KeyNotFound(format!("Invalid identifier: {identifier}")).into(),
            );
        }
        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        let pub_key: PublicKey = self.store.get::<&str, PublicKey>(&key)?.unwrap();

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();

        Wallet::from_key_manager(
            self.config.bitcoin.clone(),
            config_wallet,
            self.key_manager.clone(),
            &pub_key,
            None,
        )
    }

    pub fn clear_wallet(&self, identifier: &str) -> Result<(), anyhow::Error> {
        if identifier.trim().is_empty() {
            return Err(
                WalletError::KeyNotFound(format!("Invalid identifier: {identifier}")).into(),
            );
        }

        let store_key = StoreKey::Wallet(identifier.to_string());
        let key = store_key.get_key();
        if !self.store.has_key(&key)? {
            return Err(WalletError::KeyNotFound(key).into());
        }

        let mut config_wallet = self.config.wallet.clone();
        config_wallet.db_path = store_key.db_path();
        info!("Clearing db at {}", config_wallet.db_path);
        Wallet::clear_db(&config_wallet)?;

        Ok(())
    }

    pub fn clear_all_wallets(&self) -> Result<(), anyhow::Error> {
        let key = StoreKey::Wallet(String::new()).get_key();
        info!("key with all wallets {key}");
        for identifier_key in self.store.partial_compare_keys(&key)? {
            let identifier = identifier_key.strip_prefix(&key).unwrap().to_string();
            self.clear_wallet(&identifier)?;
        }
        Ok(())
    }

    fn get_wallet_index(&self) -> Result<u32, WalletError> {
        let key_index = StoreKey::CreateWalletIndex.get_key();
        let index = self.store.get(&key_index)?.unwrap_or(0);
        // Increment the index to save for next wallet
        self.store.set(key_index, index + 1, None)?;
        Ok(index)
    }
}
