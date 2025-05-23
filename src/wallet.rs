use crate::{config::Config, errors::WalletError};
use bitcoin::{network, Address, Amount, OutPoint, PublicKey, Transaction, Txid};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use key_manager::{key_manager::KeyManager, key_store::KeyStore};
use protocol_builder::{
    builder::Protocol,
    scripts::{self, SignMode},
    types::{input::SighashType, output::SpendMode, InputArgs, OutputType},
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
    Wallet(String),
    Funding(String, String),
    PendingTransfer(String, String),
}

impl StoreKey {
    pub fn get_key(&self) -> String {
        let base = "wallet";
        match self {
            Self::Wallet(identifier) => format!("{base}/{identifier}"),
            Self::Funding(identifier, funding_id) => {
                format!("{base}/{identifier}/funding/{funding_id}")
            }
            Self::PendingTransfer(identifier, funding_id) => {
                format!("{base}/{identifier}/transfers/{funding_id}")
            }
        }
    }
}

impl Wallet {
    pub fn new(config: Config, with_client: bool) -> Result<Wallet, WalletError> {
        let storage = Rc::new(Storage::new(&config.storage)?);
        let key_store = KeyStore::new(storage.clone());
        let key_manager = Rc::new(KeyManager::new_from_config(
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

    pub fn create_secret_key(
        &self,
        identifier: &str,
        index: u32,
    ) -> Result<PublicKey, WalletError> {
        let key = StoreKey::Wallet(identifier.to_string()).get_key();
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }
        let public = self.key_manager.derive_keypair(index)?;

        self.store.set(key, public.clone(), None)?;
        Ok(public)
    }

    pub fn import_secret_key(&self, identifier: &str, secret_key: &str) -> Result<(), WalletError> {
        let key = StoreKey::Wallet(identifier.to_string()).get_key();

        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let wallet_pub_key = self
            .key_manager
            .import_secret_key(secret_key, self.network)?;

        self.store.set(key, wallet_pub_key, None)?;

        Ok(())
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
        if self.store.has_key(&key)? {
            self.store.delete(&key)?;
            Ok(())
        } else {
            Err(WalletError::FundingNotFound(
                identifier.to_string(),
                funding_id.to_string(),
            ))
        }
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
        if self.store.has_key(&key)? {
            self.store.delete(&key)?;
            Ok(())
        } else {
            Err(WalletError::KeyNotFound(key))
        }
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
    ) -> Result<(Transaction, u64), WalletError> {
        let total_amount = origin_amount;

        if total_amount < amount.iter().sum::<u64>() + fee {
            return Err(WalletError::InsufficientFunds);
        }

        let change = total_amount - amount.iter().sum::<u64>() - fee;

        info!("Public key: {origin_pubkey}");
        let external_output = OutputType::segwit_key(total_amount, &origin_pubkey)?;
        info!("External output: {:?}", external_output);

        let mut protocol = Protocol::new("transfer_tx");
        protocol.add_external_connection(
            outpoint.txid,
            outpoint.vout,
            external_output,
            "transfer",
            &SpendMode::Segwit,
            &SighashType::ecdsa_all(),
        )?;

        for value in amount {
            info!("Amount: {value}");
            let transfer_output = if output_is_taproot {
                let sig_check =
                    scripts::check_aggregated_signature(&to_pubkey, SignMode::Aggregate);
                OutputType::taproot(*value, &to_pubkey, &[sig_check], &vec![])?
            } else {
                OutputType::segwit_key(*value, &to_pubkey)?
            };

            protocol.add_transaction_output("transfer", &transfer_output)?;
        }

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
        let key = StoreKey::Funding(identifier.to_string(), "".to_string()).get_key();
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
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Once};

    use bitcoin::hashes::Hash;
    use bitcoind::bitcoind::Bitcoind;
    use tracing::info;
    use tracing_subscriber::EnvFilter;

    use super::*;
    use anyhow::{Ok, Result};

    static INIT: Once = Once::new();

    pub fn config_trace() {
        INIT.call_once(|| {
            config_trace_aux();
        });
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
        config_trace();

        let config = bitvmx_settings::settings::load_config_file::<Config>(Some(
            "config/regtest.yaml".to_string(),
        ))?;

        clear_db(&config.storage.path);
        clear_db(&config.key_storage.path);

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
        );

        bitcoind.start()?;

        let wallet = Wallet::new(config, true)?;
        wallet.mine(101)?;

        wallet.create_secret_key("wallet_1", 0)?;
        wallet.regtest_fund("wallet_1", "fund_1", 100_000)?;
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        let pk = PublicKey::from_str(
            "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
        )?;
        wallet.fund_address("wallet_1", "fund_1", pk, &vec![9_000], 1000, false, false)?;
        wallet.confirm_transfer("wallet_1", "fund_1")?;
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        wallet.fund_address("wallet_1", "fund_1", pk, &vec![89_000], 1000, false, false)?;
        wallet.confirm_transfer("wallet_1", "fund_1")?;
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        bitcoind.stop()?;
        Ok(())
    }

    #[test]
    fn test_wallet_logic() -> Result<(), anyhow::Error> {
        config_trace();

        let config = bitvmx_settings::settings::load_config_file::<Config>(Some(
            "config/regtest.yaml".to_string(),
        ))?;

        //TODO: make temp dbs
        clear_db(&config.storage.path);
        clear_db(&config.key_storage.path);

        let wallet = Wallet::new(config, false)?;

        wallet.create_secret_key("wallet_1", 0)?;
        wallet.add_funding(
            "wallet_1",
            "fund_1",
            OutPoint {
                txid: Txid::all_zeros(),
                vout: 1,
            },
            100_000,
        )?;
        println!("YYYYY");
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        let pk = PublicKey::from_str(
            "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
        )?;
        wallet.fund_address("wallet_1", "fund_1", pk, &vec![9_000], 1000, false, false)?;
        wallet.confirm_transfer("wallet_1", "fund_1")?;
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        wallet.fund_address("wallet_1", "fund_1", pk, &vec![89_000], 1000, false, false)?;
        wallet.confirm_transfer("wallet_1", "fund_1")?;
        let funds = wallet.list_funds("wallet_1")?;
        info!("Funds: {:?}", funds);

        Ok(())
    }
}
