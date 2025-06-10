use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{network, Address, Amount, OutPoint, PrivateKey, PublicKey, Transaction, Txid};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use key_manager::{create_key_manager_from_config, key_manager::KeyManager, key_store::KeyStore};
use protocol_builder::{
    builder::Protocol,
    scripts::{self, ProtocolScript, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        InputArgs, OutputType,
    },
};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::info;

pub struct Wallet {
    store: Rc<Storage>,
    key_manager: Rc<KeyManager>,
    network: bitcoin::Network,
    bitcoin_client: Option<BitcoinClient>,
    regtest_address: Option<Address>,
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
    pub fn new(config: WalletConfig, with_client: bool) -> Result<Wallet, WalletError> {
        let storage = Rc::new(Storage::new(&config.storage)?);
        let key_store = KeyStore::new(storage.clone());
        let key_manager = Rc::new(create_key_manager_from_config(
            &config.key_manager,
            key_store,
            storage.clone(),
        )?);

        let bitcoin_client = if with_client {
            Some(BitcoinClient::new_from_config(&config.bitcoin)?)
        } else {
            None
        };

        let regtest_address = if network::Network::Regtest == config.bitcoin.network {
            if let Some(bitcoin_client) = &bitcoin_client {
                Some(
                    bitcoin_client
                        .init_wallet(bitcoin::Network::Regtest, "test_wallet")
                        .unwrap(),
                )
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            store: storage,
            key_manager,
            network: config.bitcoin.network,
            bitcoin_client,
            regtest_address,
        })
    }

    pub fn create_wallet(&self, identifier: &str) -> Result<PublicKey, WalletError> {
        let key = StoreKey::Wallet(identifier.to_string()).get_key();

        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let index = self.get_wallet_index()?;
        let public = self.key_manager.derive_keypair(index)?;

        self.store.set(key, public.clone(), None)?;

        Ok(public)
    }

    pub fn get_wallet_index(&self) -> Result<u32, WalletError> {
        let key_index = StoreKey::CreateWalletIndex.get_key();
        let index = self.store.get(&key_index)?.unwrap_or(0);
        // Increment the index to save for next wallet
        self.store.set(key_index, index + 1, None)?;
        Ok(index)
    }

    pub fn create_wallet_from_secret(
        &self,
        identifier: &str,
        secret_key: &str,
    ) -> Result<(), WalletError> {
        let key = StoreKey::Wallet(identifier.to_string()).get_key();

        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let wallet_pub_key = if secret_key.len() == 64 {
            self.key_manager
                .import_secret_key(secret_key, self.network)?
        } else {
            self.key_manager.import_private_key(secret_key)?
        };

        self.store.set(key, wallet_pub_key, None)?;

        Ok(())
    }

    pub fn export_wallet(&self, identifier: &str) -> Result<(PublicKey, PrivateKey), WalletError> {
        let key = StoreKey::Wallet(identifier.to_string()).get_key();
        let pubkey: PublicKey = self.store.get(&key)?.ok_or(WalletError::KeyNotFound(key))?;
        let secret_key = self.key_manager.export_secret(&pubkey)?;
        Ok((pubkey, secret_key))
    }

    pub fn add_funding(
        &self,
        identifier: &str,
        funding_id: &str,
        outpoint: OutPoint,
        amount: u64,
    ) -> Result<(), WalletError> {
        let key = StoreKey::Funding(identifier.to_string(), funding_id.to_string()).get_key();

        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(key));
        }

        self.store.set(key, (outpoint, amount), None)?;

        Ok(())
    }

    pub fn remove_funding(&self, identifier: &str, funding_id: &str) -> Result<(), WalletError> {
        let key = StoreKey::Funding(identifier.to_string(), funding_id.to_string()).get_key();

        if !self.store.has_key(&key)? {
            return Err(WalletError::FundingNotFound(
                identifier.to_string(),
                funding_id.to_string(),
            ));
        }

        self.store.delete(&key)?;

        Ok(())
    }

    pub fn fund_address(
        &self,
        identifier: &str,
        funding_id: &str,
        to_pubkey: PublicKey,
        amount: &Vec<u64>,
        fee: u64,
        output_is_taproot: bool,
        auto_confirm: bool,
        spending_scripts: Option<Vec<Vec<ProtocolScript>>>,
    ) -> Result<Txid, WalletError> {
        let pending_key =
            StoreKey::PendingTransfer(identifier.to_string(), funding_id.to_string()).get_key();

        if self.store.has_key(&pending_key)? {
            return Err(WalletError::TransferInProgress(pending_key));
        }

        let change_vout = amount.len() as u32;

        let key = StoreKey::Wallet(identifier.to_string()).get_key();
        let origin_pub_key: PublicKey = self
            .store
            .get(&key)?
            .ok_or(WalletError::KeyNotFound(identifier.to_string()))?;

        let key_funding =
            StoreKey::Funding(identifier.to_string(), funding_id.to_string()).get_key();
        let (outpoint, origin_amount): (OutPoint, u64) =
            self.store
                .get(&key_funding)?
                .ok_or(WalletError::FundingNotFound(
                    identifier.to_string(),
                    funding_id.to_string(),
                ))?;

        let (result, change) = self.create_transfer_transaction(
            outpoint,
            origin_amount,
            origin_pub_key,
            to_pubkey,
            amount,
            fee,
            output_is_taproot,
            spending_scripts,
        )?;

        let txid = result.compute_txid();

        self.store
            .set(pending_key, (txid, change_vout, change), None)?;

        if auto_confirm {
            self.confirm_transfer(identifier, funding_id)?;
        }

        Ok(txid)
    }

    pub fn confirm_transfer(&self, identifier: &str, funding_id: &str) -> Result<(), WalletError> {
        let key =
            StoreKey::PendingTransfer(identifier.to_string(), funding_id.to_string()).get_key();
        if let Some((txid, vout, change)) = self.store.get(&key)? {
            self.store.delete(&key)?;
            self.remove_funding(identifier, funding_id)?;
            if change > 0 {
                let outpoint = OutPoint::new(txid, vout);
                self.add_funding(identifier, funding_id, outpoint, change)?;
            }
        } else {
            return Err(WalletError::KeyNotFound(key));
        }
        Ok(())
    }

    pub fn revert_transfer(&self, identifier: &str, funding_id: &str) -> Result<(), WalletError> {
        let key =
            StoreKey::PendingTransfer(identifier.to_string(), funding_id.to_string()).get_key();

        if !self.store.has_key(&key)? {
            return Err(WalletError::KeyNotFound(key));
        }

        self.store.delete(&key)?;

        Ok(())
    }

    fn create_transfer_transaction(
        &self,
        outpoint: OutPoint,
        origin_amount: u64,
        origin_pubkey: PublicKey,
        to_pubkey: PublicKey,
        amount: &Vec<u64>,
        fee: u64,
        output_is_taproot: bool,
        spending_scripts: Option<Vec<Vec<ProtocolScript>>>,
    ) -> Result<(Transaction, u64), WalletError> {
        let total_amount_to_transfer = amount.iter().sum::<u64>();

        if origin_amount < total_amount_to_transfer + fee {
            return Err(WalletError::InsufficientFunds(format!(
                "Insufficient funds. Available: {origin_amount}, Required: {}",
                amount.iter().sum::<u64>() + fee
            )));
        }

        info!("Public key: {origin_pubkey}");
        let external_output = OutputType::segwit_key(origin_amount, &origin_pubkey)?;
        info!("External output: {:?}", external_output);

        let mut protocol = Protocol::new("transfer_tx");
        protocol.add_external_transaction("origin")?;
        protocol.add_unkwnoun_outputs("origin", outpoint.vout)?;
        protocol.add_connection(
            "origin_tx_transfer",
            "origin",
            external_output.clone().into(),
            "transfer",
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
            None,
            Some(outpoint.txid),
        )?;

        for (i, value) in amount.iter().enumerate() {
            info!("Amount: {value}");
            let transfer_output = if output_is_taproot {
                if let Some(spending_scripts) = &spending_scripts {
                    if spending_scripts.len() != amount.len() {
                        return Err(WalletError::InvalidSpendingScripts);
                    }
                    OutputType::taproot(*value, &to_pubkey, &spending_scripts[i])?
                } else {
                    let sig_check =
                        scripts::check_aggregated_signature(&to_pubkey, SignMode::Aggregate);
                    OutputType::taproot(*value, &to_pubkey, &[sig_check])?
                }
            } else {
                OutputType::segwit_key(*value, &to_pubkey)?
            };

            protocol.add_transaction_output("transfer", &transfer_output)?;
        }

        let change = origin_amount - total_amount_to_transfer - fee;

        if change > 0 {
            let change_output = OutputType::segwit_key(change, &origin_pubkey)?;
            protocol.add_transaction_output("transfer", &change_output)?;
        }

        protocol.build_and_sign(&self.key_manager, "id")?;

        let signature = protocol.input_ecdsa_signature("transfer", 0)?.unwrap();

        let mut spending_args = InputArgs::new_segwit_args();
        spending_args.push_ecdsa_signature(signature)?;

        let result = protocol.transaction_to_send("transfer", &[spending_args])?;

        if let Some(bitcoin_client) = &self.bitcoin_client {
            bitcoin_client.send_transaction(&result)?;
        }

        Ok((result, change))
    }

    pub fn mine(&self, num_blocks: u64) -> Result<(), WalletError> {
        if let Some(address) = &self.regtest_address {
            if let Some(bitcoin_client) = &self.bitcoin_client {
                bitcoin_client.mine_blocks_to_address(num_blocks, address)?;
            }
        }
        Ok(())
    }

    pub fn regtest_fund(
        &self,
        identifier: &str,
        funding_id: &str,
        amount: u64,
    ) -> Result<(), WalletError> {
        if let Some(bitcoin_client) = &self.bitcoin_client {
            let key = StoreKey::Wallet(identifier.to_string()).get_key();
            let origin_pub_key: PublicKey = self
                .store
                .get(&key)?
                .ok_or(WalletError::KeyNotFound(identifier.to_string()))?;
            let address = bitcoin_client.get_new_address(origin_pub_key, self.network);
            let (tx, vout) = bitcoin_client.fund_address(&address, Amount::from_sat(amount))?;
            let txid = tx.compute_txid();
            self.add_funding(identifier, funding_id, OutPoint { txid, vout }, amount)?;
        }
        Ok(())
    }

    pub fn list_funds(
        &self,
        identifier: &str,
    ) -> Result<Vec<(String, OutPoint, u64)>, WalletError> {
        let key = StoreKey::Funding(identifier.to_string(), String::new()).get_key();
        let mut funds = Vec::new();
        for identifier_key in self.store.partial_compare_keys(&key)? {
            if let Some((outpoint, value)) = self.store.get(&identifier_key)? {
                funds.push((
                    identifier_key.strip_prefix(&key).unwrap().to_string(),
                    outpoint,
                    value,
                ));
            }
        }
        Ok(funds)
    }

    pub fn get_wallets(&self) -> Result<Vec<(String, PublicKey)>, WalletError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Ok, Result};
    use bitcoin::{hashes::Hash, key::{rand, Secp256k1}, secp256k1::{self, SecretKey}, Network};
    use bitcoind::bitcoind::Bitcoind;
    use musig2::{secp256k1::{PublicKey as MusigPublicKey, SecretKey as MusigSecretKey}, KeyAggContext};
    use std::{str::FromStr, sync::Once};
    use tracing::info;
    use tracing_subscriber::EnvFilter;

    static INIT: Once = Once::new();

    pub fn config_trace() {
        INIT.call_once(|| {
            config_trace_aux();
        });
    }

    fn generate_random_string() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..10).map(|_| rng.gen_range('a'..='z')).collect()
    }

    fn clean_and_load_config(config_path: &str) -> Result<WalletConfig, anyhow::Error> {
        let base_path = "/tmp/test_wallet";

        clear_db(&base_path);

        config_trace();

        let mut config = bitvmx_settings::settings::load_config_file::<WalletConfig>(Some(
            config_path.to_string(),
        ))?;

        let storage_path = format!("{base_path}/{}/storage.db", generate_random_string());
        let key_storage_path = format!("{base_path}/{}/keys.db", generate_random_string());

        config.storage.path = storage_path;
        config.key_storage.path = key_storage_path;

        Ok(config)
    }

    fn config_trace_aux() {
        let default_modules = ["info"];

        let filter = EnvFilter::builder()
            .parse(default_modules.join(","))
            .expect("Invalid filter");

        tracing_subscriber::fmt()
            .with_target(true)
            .with_env_filter(filter)
            .init();
    }

    fn clear_db(path: &str) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    #[ignore]
    fn test_fund_address() -> Result<(), anyhow::Error> {
        let config = clean_and_load_config("config/regtest.yaml")?;

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
        );

        bitcoind.start()?;

        let wallet = Wallet::new(config, true)?;
        wallet.mine(101)?;

        let wallet_name = "wallet_1";
        let funding_id = "fund_1";

        wallet.create_wallet(wallet_name)?;
        wallet.regtest_fund(wallet_name, funding_id, 100_000)?;
        let funds = wallet.list_funds(wallet_name)?;
        assert_eq!(funds.len(), 1);
        assert_eq!(funds[0].2, 100_000);

        let pk = PublicKey::from_str(
            "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
        )?;
        wallet.fund_address(
            wallet_name,
            funding_id,
            pk,
            &vec![9_000],
            1000,
            false,
            false,
            None,
        )?;
        wallet.confirm_transfer(wallet_name, funding_id)?;
        let funds = wallet.list_funds(wallet_name)?;
        info!("Funds: {:?}", funds);

        wallet.fund_address(
            wallet_name,
            funding_id,
            pk,
            &vec![89_000],
            1000,
            false,
            false,
            None,
        )?;
        wallet.confirm_transfer(wallet_name, funding_id)?;
        let funds = wallet.list_funds(wallet_name)?;
        info!("Funds: {:?}", funds);

        bitcoind.stop()?;
        Ok(())
    }

    #[test]
    fn test_wallet_logic() -> Result<(), anyhow::Error> {
        let config = clean_and_load_config("config/regtest.yaml")?;

        let wallet = Wallet::new(config, false)?;

        let wallet_name = "wallet_1";
        let funding_id = "fund_1";

        wallet.create_wallet(wallet_name)?;
        wallet.add_funding(
            wallet_name,
            funding_id,
            OutPoint {
                txid: Txid::all_zeros(),
                vout: 1,
            },
            100_000,
        )?;
        let funds = wallet.list_funds(wallet_name)?;
        info!("Funds: {:?}", funds);

        let pk = PublicKey::from_str(
            "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
        )?;
        wallet.fund_address(
            wallet_name,
            funding_id,
            pk,
            &vec![9_000],
            1000,
            false,
            false,
            None,
        )?;
        wallet.confirm_transfer(wallet_name, funding_id)?;
        let funds = wallet.list_funds(wallet_name)?;
        info!("Funds: {:?}", funds);

        wallet.fund_address(
            wallet_name,
            funding_id,
            pk,
            &vec![89_000],
            1000,
            false,
            false,
            None,
        )?;
        wallet.confirm_transfer(wallet_name, funding_id)?;
        let funds = wallet.list_funds(wallet_name)?;
        info!("Funds: {:?}", funds);

        Ok(())
    }

    #[test]
    fn test_get_wallets() -> Result<(), anyhow::Error> {
        let config = clean_and_load_config("config/regtest.yaml")?;

        let wallet = Wallet::new(config, false)?;

        // Create 3 wallets with different identifiers and indices
        let wallet_names = vec!["wallet1", "wallet2", "wallet3"];

        for name in wallet_names.iter() {
            wallet.create_wallet(name)?;
        }

        let wallets = wallet.get_wallets()?;

        // Check if all expected wallet names are present
        for (wallet_name, _) in wallets {
            assert!(wallet_names.contains(&wallet_name.as_str()));
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_create_wallet_from_secret() -> Result<(), anyhow::Error> {
        let config = clean_and_load_config("config/regtest.yaml")?;

        let wallet = Wallet::new(config, false)?;

        let secret_key_str = "01010101010101010001020304050607ffff0000ffff00006363636363636363";
        let secret_key = SecretKey::from_str(secret_key_str)?;
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let private_key_str = private_key.to_string();

        wallet.create_wallet_from_secret("wallet_1", &secret_key_str)?;
        wallet.create_wallet_from_secret("wallet_2", &private_key_str)?;
        let (_, secret_key_wallet_1) = wallet.export_wallet("wallet_1")?;
        let (_, secret_key_wallet_2) = wallet.export_wallet("wallet_2")?;

        assert_eq!(secret_key_wallet_1, private_key);
        assert_eq!(secret_key_wallet_2, private_key);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_use_private_musig_to_fund_address() {
        let config = clean_and_load_config("config/regtest.yaml").unwrap();

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
        );

        bitcoind.start().unwrap();

        let wallet = Wallet::new(config, true).unwrap();
        wallet.mine(101).unwrap();

        let wallet_name = "wallet_1";
        let funding_id = "fund_1";

        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let mut private_keys = Vec::new();
        let mut public_keys: Vec<MusigPublicKey> = Vec::new();
        
        // Generate 5 random private keys and their corresponding public keys
        for _ in 0..5{
            let privkey = SecretKey::new(&mut rng);
            let musig_secret = MusigSecretKey::from_byte_array(&privkey.secret_bytes()).unwrap();
            let musig_scalar = musig2::secp::Scalar::from_slice(&musig_secret.secret_bytes()).unwrap();
            private_keys.push(musig_scalar);
            let pubkey = privkey.public_key(&secp);
            let pubkey = MusigPublicKey::from_str(&pubkey.to_string()).unwrap();
            public_keys.push(pubkey);
        }

        // Create Aggregated public key and secret key
        let ctx = KeyAggContext::new(public_keys).unwrap();
        let aggregated_pubkey: MusigPublicKey = ctx.aggregated_pubkey();
        let aggregated_pubkey = PublicKey::from_str(&aggregated_pubkey.to_string()).unwrap();
        let aggregated_seckey: MusigSecretKey = ctx.aggregated_seckey(private_keys).unwrap();
        let aggregated_seckey = SecretKey::from_str(&aggregated_seckey.display_secret().to_string()).unwrap();
        let aggregated_private_key = PrivateKey::new(aggregated_seckey, Network::Regtest);
        let public_key = aggregated_private_key.public_key(&secp);

        // Check if the aggregated public key matches the public key derived from the aggregated secret key
        assert_eq!(public_key, aggregated_pubkey);

        // Create a wallet with the aggregated secret key and fund it
        wallet.create_wallet_from_secret(wallet_name, &aggregated_seckey.display_secret().to_string()).unwrap();
        wallet.regtest_fund(wallet_name, funding_id, 100_000).unwrap();

        let pk = PublicKey::from_str(
            "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
        ).unwrap();

        let result = wallet.fund_address(
            wallet_name,
            funding_id,
            pk,
            &vec![9_000],
            1000,
            true,
            true,
            None,
        );
        assert!(result.is_ok(), "Failed to fund address: {:?}", result.err());
    }
}
