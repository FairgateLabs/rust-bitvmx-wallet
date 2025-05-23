use crate::errors::WalletError;
use bitcoin::{network, OutPoint, PublicKey, Transaction, Txid};
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    rpc_config::RpcConfig,
};
use key_manager::key_manager::KeyManager;
use protocol_builder::{
    builder::Protocol,
    types::{input::SighashType, output::SpendMode, InputArgs, OutputType},
};
use std::{env, process::id, rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

pub struct Wallet {
    store: Rc<Storage>,
    key_manager: Rc<KeyManager>,
    network: bitcoin::Network,
}

impl Wallet {
    pub fn new(
        store: Rc<Storage>,
        key_manager: Rc<KeyManager>,
        network: bitcoin::Network,
    ) -> Result<Wallet, WalletError> {
        Ok(Self {
            store,
            key_manager,
            network,
        })
    }

    fn key_identifier(&self, identifier: &str) -> String {
        format!("wallet/{}", identifier)
    }

    fn key_funding(&self, identifier: &str, funding_id: &str) -> String {
        format!("wallet/{}/funding/{}", identifier, funding_id)
    }

    fn pending_transfer(&self, identifier: &str, funding_id: &str) -> String {
        format!("wallet/{}/transfers/{}", identifier, funding_id)
    }

    pub fn import_secret_key(&self, identifier: &str, secret_key: &str) -> Result<(), WalletError> {
        if self.store.has_key(&self.key_identifier(identifier))? {
            return Err(WalletError::KeyAlreadyExists(identifier.to_string()));
        }

        let wallet_pub_key = self
            .key_manager
            .import_secret_key(secret_key, self.network)?;

        self.store
            .set(self.key_identifier(identifier), wallet_pub_key, None)?;

        Ok(())
    }

    pub fn add_funding(
        &self,
        identifier: &str,
        funding_id: &str,
        outpoint: OutPoint,
        amount: u64,
    ) -> Result<(), WalletError> {
        let key = self.key_funding(identifier, funding_id);
        if self.store.has_key(&key)? {
            return Err(WalletError::KeyAlreadyExists(key));
        }
        self.store.set(key, (outpoint, amount), None)?;
        Ok(())
    }

    pub fn remove_funding(&self, identifier: &str, funding_id: &str) -> Result<(), WalletError> {
        let key = self.key_funding(identifier, funding_id);
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
        amount: u64,
        fee: u64,
    ) -> Result<Txid, WalletError> {
        let key = self.pending_transfer(identifier, funding_id);
        if self.store.has_key(&key)? {
            return Err(WalletError::TransferInProgress(key));
        }

        let origin_pub_key: PublicKey = self
            .store
            .get(&self.key_identifier(identifier))?
            .ok_or(WalletError::KeyNotFound(identifier.to_string()))?;
        let (outpoint, origin_amount): (OutPoint, u64) = self
            .store
            .get(&self.key_funding(identifier, funding_id))?
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
        )?;

        let txid = result.compute_txid();

        self.store.set(key, (txid, 1, change), None)?;

        Ok(txid)
    }

    pub fn confirm_transfer(&self, identifier: &str, funding_id: &str) -> Result<(), WalletError> {
        let key = self.pending_transfer(identifier, funding_id);
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
        let key = self.pending_transfer(identifier, funding_id);
        if self.store.has_key(&key)? {
            self.store.delete(&key)?;
            Ok(())
        } else {
            Err(WalletError::KeyNotFound(key))
        }
    }

    pub fn create_transfer_transaction(
        &self,
        outpoint: OutPoint,
        origin_amount: u64,
        origin_pubkey: PublicKey,
        to_pubkey: PublicKey,
        amount: u64,
        fee: u64,
    ) -> Result<(Transaction, u64), WalletError> {
        let total_amount = origin_amount;

        if total_amount < amount + fee {
            return Err(WalletError::InsufficientFunds);
        }

        let change = total_amount - amount - fee;

        let external_output = OutputType::segwit_key(total_amount, &origin_pubkey)?;
        let transfer_output = OutputType::segwit_key(amount, &to_pubkey)?;

        let mut protocol = Protocol::new("transfer_tx");
        protocol
            .add_external_connection(
                outpoint.txid,
                outpoint.vout,
                external_output,
                "transfer",
                &SpendMode::Segwit,
                &SighashType::ecdsa_all(),
            )?
            // Transfer output
            .add_transaction_output("transfer", &transfer_output)?;

        if change > 0 {
            let change_output = OutputType::segwit_key(change, &origin_pubkey)?;
            protocol.add_transaction_output("transfer", &change_output)?;
        }

        protocol.build_and_sign(&self.key_manager, "id")?;

        let signature = protocol.input_ecdsa_signature("transfer", 0)?.unwrap();

        let mut spending_args = InputArgs::new_segwit_args();
        spending_args.push_ecdsa_signature(signature)?;

        let result = protocol.transaction_to_send("transfer", &[spending_args])?;

        Ok((result, change))
    }

    pub fn list_funds(
        &self,
        identifier: &str,
    ) -> Result<Vec<(String, OutPoint, u64)>, WalletError> {
        let key = self.key_funding(identifier, "");
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
    use bitcoin::Network;
    use bitcoind::bitcoind::Bitcoind;
    use key_manager::{config::KeyManagerConfig, key_store::KeyStore};

    use super::*;
    use crate::config::Config;
    use anyhow::{Ok, Result};

    #[test]
    fn test_fund_address() -> Result<(), anyhow::Error> {
        let config = bitvmx_settings::settings::load::<Config>()?;

        let bitcoind = Bitcoind::new(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
        );

        bitcoind.start()?;

        let bitcoin_client = BitcoinClient::new_from_config(&config.bitcoin)?;
        let wallet = bitcoin_client.init_wallet(Network::Regtest, "test_wallet");

        if wallet.is_ok() {
            let address = wallet.unwrap();
            bitcoin_client.mine_blocks_to_address(100, &address)?;
        }

        let storage = Rc::new(Storage::new(&config.storage)?);
        let key_manager_config =
            KeyManagerConfig::new(config.bitcoin.network.to_string(), None, None, None);
        let key_store = KeyStore::new(storage.clone());
        let key_manager = Rc::new(KeyManager::new_from_config(
            &key_manager_config,
            key_store,
            storage.clone(),
        )?);

        let wallet = Wallet::new(
            config.bitcoin,
            storage,
            key_manager.clone(),
            WalletConfig::new("some-private-key".to_string()),
        )?;

        let funding_txid =
            Txid::from_str("9946702831bccfaa40c8a9018a35b8633031201ccb85ca2e9648ad5ec8892d26")
                .unwrap(); // Replace with the correct txid
        let vout = 10; // Replace with the correct vout
        let amount = wallet
            .bitcoin_client
            .get_tx_out(&funding_txid, vout)
            .unwrap()
            .value
            .to_sat()
            / 10;

        let result = wallet.fund_address(wallet.pub_key, amount);
        assert!(result.is_ok(), "Failed to fund address: {:?}", result.err());
        println!("Transaction ID: {}", result.unwrap());

        Ok(())
    }
}
