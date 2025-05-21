use std::{env, rc::Rc, str::FromStr};

use bitcoin::{
    secp256k1::SecretKey, Address, CompressedPublicKey, Network, PrivateKey, PublicKey, Txid,
};
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    rpc_config::RpcConfig,
};
use dotenvy::from_path;
use key_manager::{config::KeyManagerConfig, key_manager::KeyManager, key_store::KeyStore};
use protocol_builder::{
    builder::Protocol,
    types::{input::SighashType, InputArgs, OutputType},
};
use storage_backend::{storage::Storage, storage_config::StorageConfig};

use crate::errors::WalletError;

pub struct Wallet {
    network: Network,
    client: BitcoinClient,
    key_manager: Rc<KeyManager>,
    pk: PublicKey,
}

impl Wallet {
    pub fn new(
        bitcoin_client_config: RpcConfig,
        key_manager_config: KeyManagerConfig,
        key_store_config: StorageConfig,
        storage_config: StorageConfig,
    ) -> Wallet {
        let network = bitcoin_client_config.network;
        from_path("config/.env").expect("Failed to load .env from config/");
        let client = BitcoinClient::new(
            &bitcoin_client_config.url,
            &bitcoin_client_config.username,
            &bitcoin_client_config.password,
        )
        .unwrap();

        let keystore = KeyStore::new(Rc::new(Storage::new(&key_store_config).unwrap()));
        let store = Rc::new(Storage::new(&storage_config).unwrap());
        let key_manager = Rc::new(key_manager::create_key_manager_from_config(
            &key_manager_config,
            keystore,
            store,
        ).unwrap());

        let secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let secret_key = SecretKey::from_str(&secret_key).unwrap();
        let private_key = PrivateKey::new(secret_key, network);

        let pk = key_manager
            .import_private_key(&private_key.to_string())
            .unwrap();

        Wallet {
            network,
            client,
            key_manager,
            pk,
        }
    }

    pub fn fund_address(
        &self,
        funding_txid: Txid,
        vout: u32,
        to_pubkey: PublicKey,
        amount: u64,
        fee: u64,
    ) -> Result<Txid, WalletError> {
        let output = self.client.get_tx_out(&funding_txid, vout)?;
        let total_amount = output.value.to_sat();
        let (change, value) = if total_amount > amount + fee {
            (total_amount - amount - fee, amount)
        } else if total_amount == amount + fee {
            (0, total_amount - fee)
        } else {
            panic!("Not enough funds in the funding transaction");
        };

        let external_output = OutputType::segwit_key(total_amount, &self.pk)?;
        let transfer_output = OutputType::segwit_key(value, &to_pubkey)?;

        let mut protocol = Protocol::new("transfer_tx");
        protocol
            .add_external_connection(
                funding_txid,
                vout,
                external_output,
                "transfer",
                &SighashType::ecdsa_all(),
            )?
            // Transfer output
            .add_transaction_output("transfer", &transfer_output)?;

        if change > 0 {
            let change_output = OutputType::segwit_key(change, &self.pk)?;
            protocol.add_transaction_output("transfer", &change_output)?;
        }

        protocol.build_and_sign(&self.key_manager, "id")?;

        let signature = protocol.input_ecdsa_signature("transfer", 0)?.unwrap();

        let mut spending_args = InputArgs::new_segwit_args();
        spending_args.push_ecdsa_signature(signature)?;

        let tx = protocol.transaction_to_send("transfer", &[spending_args])?;

        let result = self.client.send_transaction(&tx)?;
        Ok(result)
    }

    pub fn get_pubkey(&self) -> PublicKey {
        self.pk
    }

    pub fn get_secret_key(&self) -> Result<SecretKey, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let secret_key = SecretKey::from_str(&user_secret_key).unwrap();

        Ok(secret_key)
    }

    pub fn get_address(&self) -> Result<Address, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let user_pubkey = self
            .key_manager
            .import_secret_key(&user_secret_key, self.network)?;
        let compressed_pubkey = CompressedPublicKey::from_slice(&user_pubkey.to_bytes()).unwrap();

        let address = Address::p2wpkh(&compressed_pubkey, self.network);

        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use super::*;

    #[test]
    fn test_fund_address() {
        let config = Config::new().unwrap();

        let wallet = Wallet::new(
            config.bitcoin,
            config.key_manager,
            config.key_storage,
            config.storage,
        );

        let funding_txid = Txid::from_str("9946702831bccfaa40c8a9018a35b8633031201ccb85ca2e9648ad5ec8892d26").unwrap(); // Replace with the correct txid
        let vout = 10; // Replace with the correct vout
        let to_pubkey = wallet.get_pubkey();
        let amount = wallet.client.get_tx_out(&funding_txid, vout).unwrap().value.to_sat()/10;
        let fee = 150;

        let result = wallet.fund_address(funding_txid, vout, to_pubkey, amount, fee);
        assert!(result.is_ok(), "Failed to fund address: {:?}", result.err());
        println!("Transaction ID: {}", result.unwrap());
    }
}
