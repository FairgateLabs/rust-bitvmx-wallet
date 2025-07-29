use std::{fmt, sync::Arc};
use bitcoin::{ecdsa, secp256k1::{All, Secp256k1}, sighash, PublicKey, Psbt};
use bdk_wallet::{signer::{InputSigner, SignerCommon, SignerError, SignerId}, SignOptions};
use key_manager::key_manager::KeyManager;

/// Wrapper struct to implement bdk_wallet::InputSigner for KeyManager as it cannot be used directly
/// due to rust orphan rule (only traits defined in the current crate can be implemented for types defined outside of the crate)
/// This is used to sign inputs of a PSBT using the KeyManager
pub struct KeyManagerSigner {
    key_manager: Arc<KeyManager>,
    public_key: PublicKey,
}

impl KeyManagerSigner {
    pub fn new(key_manager: Arc<KeyManager>, public_key: PublicKey) -> Result<Self, anyhow::Error> {
        Ok(Self { key_manager, public_key })
    }
}
// Implement Debug for KeyManagerSigner
impl fmt::Debug for KeyManagerSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManagerSigner")
         .field("public_key", &self.public_key)
         .finish()
    }
}


impl SignerCommon for KeyManagerSigner {
    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        let hash = self.public_key.pubkey_hash();
        SignerId::PkHash(hash.into())
    }
    
    fn descriptor_secret_key(&self) -> Option<bdk_wallet::keys::DescriptorSecretKey> {
        None
    }
}

impl InputSigner for KeyManagerSigner {
    fn sign_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        _sign_options: &SignOptions,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        if psbt.inputs[input_index].final_script_sig.is_some()
            || psbt.inputs[input_index].final_script_witness.is_some()
        {
            return Ok(());
        }

        if psbt.inputs[input_index].partial_sigs.contains_key(&self.public_key) {
            return Ok(());
        }

        let mut sighasher = sighash::SighashCache::new(psbt.unsigned_tx.clone());
        let (msg, sighash_type) = psbt
            .sighash_ecdsa(input_index, &mut sighasher)
            .map_err(SignerError::Psbt)?;

        let signature = self.key_manager.sign_ecdsa_message(&msg, &self.public_key)
            .map_err(|e| SignerError::External(e.to_string()))?;

        _secp.verify_ecdsa(&msg, &signature, &self.public_key.inner).expect("invalid or corrupted ecdsa signature");

        let final_signature = ecdsa::Signature {
            signature,
            sighash_type,
        };
        psbt.inputs[input_index].partial_sigs.insert(self.public_key.clone(), final_signature);

        Ok(())
    }
}

