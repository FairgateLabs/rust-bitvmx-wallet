use crate::{config::WalletConfig, errors::WalletError};
use bitcoin::{secp256k1::SecretKey, OutPoint, PublicKey, Transaction, Txid};
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    rpc_config::RpcConfig,
};
use key_manager::key_manager::KeyManager;
use protocol_builder::{
    builder::Protocol,
    types::{input::SighashType, output::SpendMode, InputArgs, OutputType},
};
use std::{env, rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

pub struct Wallet {
    bitcoin_client: BitcoinClient,
    store: Rc<Storage>,
    key_manager: Rc<KeyManager>,
    pub pub_key: PublicKey,
}

impl Wallet {
    pub fn new(
        bitcoin_client_config: RpcConfig,
        store: Rc<Storage>,
        key_manager: Rc<KeyManager>,
        wallet_config: WalletConfig,
    ) -> Result<Wallet, WalletError> {
        let network = bitcoin_client_config.network;
        let bitcoin_client = BitcoinClient::new_from_config(&bitcoin_client_config)?;
        let wallet_pub_key = key_manager.import_secret_key(&wallet_config.private_key, network)?;

        Ok(Self {
            bitcoin_client,
            store,
            key_manager,
            pub_key: wallet_pub_key,
        })
    }

    pub fn add_funding(&self, outpoint: OutPoint) -> Result<(), WalletError> {
        let key = "wallet/funding";
        self.store.set(key, outpoint, None)?;
        Ok(())
    }

    pub fn fund_address(&self, to_pubkey: PublicKey, amount: u64) -> Result<Txid, WalletError> {
        let key = "wallet/funding";
        let outpoint: OutPoint = self.store.get(&key)?.ok_or(WalletError::FundingNotFound)?;

        let result = self.create_transfer_transaction(outpoint, to_pubkey, amount)?;

        Ok(result.compute_txid())
    }

    pub fn create_transfer_transaction(
        &self,
        outpoint: OutPoint,
        to_pubkey: PublicKey,
        amount: u64,
    ) -> Result<Transaction, WalletError> {
        let fee = 150; // TODO: Make this configurable

        let output = self
            .bitcoin_client
            .get_tx_out(&outpoint.txid, outpoint.vout)?;

        let total_amount = output.value.to_sat();

        if total_amount < amount + fee {
            return Err(WalletError::InsufficientFunds);
        }

        let change = total_amount - amount - fee;

        let external_output = OutputType::segwit_key(total_amount, &self.pub_key)?;
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
            let change_output = OutputType::segwit_key(change, &self.pub_key)?;
            protocol.add_transaction_output("transfer", &change_output)?;
        }

        protocol.build_and_sign(&self.key_manager, "id")?;

        let signature = protocol.input_ecdsa_signature("transfer", 0)?.unwrap();

        let mut spending_args = InputArgs::new_segwit_args();
        spending_args.push_ecdsa_signature(signature)?;

        let result = protocol.transaction_to_send("transfer", &[spending_args])?;

        Ok(result)
    }

    pub fn get_secret_key() -> Result<SecretKey, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let secret_key = SecretKey::from_str(&user_secret_key).unwrap();
        Ok(secret_key)
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
        let config = Config::new(Some("config/development.yaml".to_string()))?;

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

        let wallet = Wallet::new(config.bitcoin, storage, key_manager.clone(), config.wallet)?;

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
