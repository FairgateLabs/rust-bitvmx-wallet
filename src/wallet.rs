use std::{env, rc::Rc, str::FromStr};

use bitcoin::{secp256k1::SecretKey, Address, CompressedPublicKey, Network, PublicKey, Transaction, Txid};
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    rpc_config::RpcConfig,
};
use dotenvy::from_path;
use key_manager::{
    key_manager::KeyManager,    
};
use protocol_builder::{
    builder::Protocol,
    types::{input::SighashType, InputArgs, OutputType},
};

use crate::errors::WalletError;

pub struct Wallet {
    network: Network,
    client: BitcoinClient,
    key_manager: Rc<KeyManager>,
}

impl Wallet {
    pub fn new(
        network: Network,
        bitcoin_client_config: RpcConfig,
        key_manager: KeyManager
    ) -> Wallet {

        from_path("config/.env").expect("Failed to load .env from config/");
        let client = BitcoinClient::new(
            &bitcoin_client_config.url,
            &bitcoin_client_config.username,
            &bitcoin_client_config.password,
        )
        .unwrap();
        let key_manager = Rc::new(key_manager);

        Wallet { network, client, key_manager }
    }

    pub fn fund_tx(
        &self,
        funding_txid: Txid,
        vout: u32,
        to_pubkey: PublicKey,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        let output = self.client.get_tx_out(&funding_txid, vout)?;
        let total_amount = output.value.to_sat();
        let (change, value) = if total_amount > amount + fee {
            (total_amount - amount - fee, amount)
        } else if total_amount == amount + fee {
            (0, total_amount - fee)
        } else {
            panic!("Not enough funds in the funding transaction");
        };
        
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let user_pubkey = self.key_manager.import_secret_key(&user_secret_key, self.network)?;


        let external_output = OutputType::segwit_key(total_amount, &user_pubkey)?;
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
            let change_output = OutputType::segwit_key(change, &user_pubkey)?;
            protocol.add_transaction_output("transfer", &change_output)?;
        }

        protocol.build_and_sign(&self.key_manager, "id")?;

        let signature = protocol.input_ecdsa_signature("transfer", 0)?.unwrap();

        let mut spending_args = InputArgs::new_segwit_args();
        spending_args.push_ecdsa_signature(signature)?;

        let result = protocol.transaction_to_send("transfer", &[spending_args])?;

        Ok(result)
    }

    pub fn get_pubkey(&self) -> Result<PublicKey, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let user_pubkey = self.key_manager.import_secret_key(&user_secret_key, self.network)?;
        Ok(user_pubkey)

    }

    pub fn get_secret_key(&self) -> Result<SecretKey, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let secret_key = SecretKey::from_str(&user_secret_key).unwrap();

        Ok(secret_key)
    }

    pub fn get_address(&self) -> Result<Address, WalletError> {
        let user_secret_key = env::var("USER_SECRET_KEY").expect("USER_SECRET_KEY must be set");
        let user_pubkey = self.key_manager.import_secret_key(&user_secret_key, self.network)?;
        let compressed_pubkey = CompressedPublicKey::from_slice(&user_pubkey.to_bytes()).unwrap();

        let address = Address::p2wpkh(&compressed_pubkey, self.network);

        Ok(address)
    }

}
