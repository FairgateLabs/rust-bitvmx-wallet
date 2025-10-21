use std::time::{SystemTime, UNIX_EPOCH};

use crate::wallet::errors::WalletError;
use bitcoin::key::Secp256k1;
use bitcoin::XOnlyPublicKey;
use bitcoin::{Address, Network, PublicKey, ScriptBuf};
use protocol_builder::scripts::{self, ProtocolScript};

/// Converts a public key to a Pay-to-Witness-Public-Key-Hash (P2WPKH) Bitcoin address.
///
/// P2WPKH is a native SegWit address type that provides better security and lower transaction fees
/// compared to legacy P2PKH addresses. The public key is hashed using SHA256 and RIPEMD160 to
/// create a 20-byte hash that is then encoded as a Bech32 address.
///
/// # Arguments
///
/// * `public_key` - The secp256k1 public key to convert to an address
/// * `network` - The Bitcoin network (mainnet, testnet, regtest, or signet)
///
/// # Returns
///
/// * `Ok(Address)` - The P2WPKH address for the given public key and network
/// * `Err(WalletError)` - If the public key is invalid or address creation fails
///
/// # Example
///
/// ```rust
/// use bitcoin::{Network, PublicKey};
/// use bitvmx_wallet::wallet::utils::pub_key_to_p2wpkh;
///
/// let public_key = PublicKey::from_str("...").unwrap();
/// let address = pub_key_to_p2wpkh(&public_key, Network::Testnet)?;
/// println!("P2WPKH Address: {}", address);
/// ```
pub fn pub_key_to_p2wpkh(public_key: &PublicKey, network: Network) -> Result<Address, WalletError> {
    let script = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);
    let address = Address::from_script(&script, network)?;
    Ok(address)
}

/// Converts an x-only public key to a Pay-to-Taproot (P2TR) Bitcoin address.
///
/// P2TR is the native SegWit v1 address type that enables Taproot functionality, providing
/// enhanced privacy and efficiency. This function creates a Taproot output by building a
/// Taproot spend info from the x-only public key and optional tap leaves (scripts).
///
/// The function constructs a Taproot tree with the provided tap leaves and uses the x-only
/// public key as the internal key. The resulting output key is then used to create a P2TR
/// script and address.
///
/// # Arguments
///
/// * `x_public_key` - The x-only public key (32 bytes) to use as the internal key
/// * `tap_leaves` - Optional array of protocol scripts to include in the Taproot tree
/// * `network` - The Bitcoin network (mainnet, testnet, regtest, or signet)
///
/// # Returns
///
/// * `Ok(Address)` - The P2TR address for the given x-only public key and tap leaves
/// * `Err(WalletError)` - If the Taproot spend info creation or address generation fails
///
/// # Example
///
/// ```rust
/// use bitcoin::{Network, XOnlyPublicKey};
/// use bitvmx_wallet::wallet::utils::pub_key_to_p2tr;
/// use protocol_builder::scripts::ProtocolScript;
///
/// let x_pubkey = XOnlyPublicKey::from_str("...").unwrap();
/// let tap_leaves = vec![/* protocol scripts */];
/// let address = pub_key_to_p2tr(&x_pubkey, &tap_leaves, Network::Testnet)?;
/// println!("P2TR Address: {}", address);
/// ```
pub fn pub_key_to_p2tr(
    x_public_key: &XOnlyPublicKey,
    tap_leaves: &[ProtocolScript],
    network: Network,
) -> Result<Address, WalletError> {
    let tap_spend_info =
        scripts::build_taproot_spend_info(&Secp256k1::new(), x_public_key, tap_leaves)?;
    let script = ScriptBuf::new_p2tr_tweaked(tap_spend_info.output_key());
    let address = Address::from_script(&script, network)?;
    Ok(address)
}

/// Creates a P2WPKH (Pay-to-Witness-Public-Key-Hash) descriptor.
///
/// This function creates a native SegWit descriptor using a private key in WIF format.
/// P2WPKH addresses provide better security and lower transaction fees compared to legacy addresses.
///
/// # Arguments
///
/// * `private_key` - Private key in WIF (Wallet Import Format)
///
/// # Returns
///
/// A `Result` containing the descriptor string or an error.
///
/// # Notes
///
/// The descriptor format follows the Bitcoin descriptor specification:
/// - `wpkh()` indicates native SegWit private key in WIF format
/// - See [BDK descriptor documentation](https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/macro.descriptor.html)
/// - See [Bitcoin descriptor specification](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples)
///
/// # Example
///
/// ```rust
/// let descriptor = Wallet::p2wpkh_descriptor(
///     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o"
/// )?;
/// // Returns: "wpkh(L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o)"
/// ```
pub fn p2wpkh_descriptor(private_key: &str) -> Result<String, WalletError> {
    // This descriptor for the wallet, wpkh indicates native segwit private key in wif format
    // See https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/macro.descriptor.html
    // and https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples
    Ok(format!("wpkh({private_key})"))
}

/// Creates a P2TR (Pay-to-Taproot) descriptor.
///
/// This function creates a Taproot descriptor using a private key in WIF format.
/// P2TR addresses provide the latest Bitcoin address format with enhanced privacy and efficiency.
///
/// # Arguments
///
/// * `private_key` - Private key in WIF (Wallet Import Format)
///
/// # Returns
///
/// A `Result` containing the descriptor string or an error.
///
/// # Notes
///
/// The descriptor format follows the Bitcoin descriptor specification:
/// - `tr()` indicates P2TR output with the specified key as internal key
/// - See [Bitcoin descriptor specification](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples)
///
/// # Example
///
/// ```rust
/// let descriptor = Wallet::p2tr_descriptor(
///     "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o"
/// )?;
/// // Returns: "tr(L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o)"
/// ```
pub fn p2tr_descriptor(private_key: &str) -> Result<String, WalletError> {
    // P2TR output with the specified key as internal key, and optionally a tree of script paths.
    // tr(KEY) or tr(KEY,TREE) (top level only): P2TR output with the specified key as internal key, and optionally a tree of script paths.
    // See https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples
    Ok(format!("tr({private_key})"))
}

/// Gets the current Unix timestamp in seconds.
///
/// This function returns the current time as a Unix timestamp (seconds since
/// the Unix epoch: January 1, 1970, 00:00:00 UTC).
///
/// # Returns
///
/// A `Result` containing:
/// * `Ok(u64)` - The current Unix timestamp in seconds
/// * `Err(WalletError)` - If there's an error getting the current time
///
/// # Example
///
/// ```rust
/// use bitvmx_wallet::wallet::utils::get_current_timestamp;
///
/// let timestamp = get_current_timestamp()?;
/// println!("Current timestamp: {}", timestamp);
/// ```
pub fn get_current_timestamp() -> Result<u64, WalletError> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(timestamp)
}
