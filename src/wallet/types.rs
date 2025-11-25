use protocol_builder::bitcoin::{Block, PublicKey, XOnlyPublicKey};
use protocol_builder::scripts::ProtocolScript;
use serde::{Deserialize, Serialize};

/// Events that can be emitted during wallet synchronization.
///
/// This enum represents different types of events that can occur during
/// blockchain synchronization, including termination signals and blockchain events.
#[derive(Debug)]
pub enum Emission {
    /// Signal termination event (SIGTERM).
    ///
    /// Used to gracefully shut down synchronization processes.
    SigTerm,

    /// New block event.
    ///
    /// Contains information about a new block that has been added to the blockchain.
    Block(bdk_bitcoind_rpc::BlockEvent<Block>),

    /// Mempool event.
    ///
    /// Contains information about changes in the transaction mempool.
    Mempool(bdk_bitcoind_rpc::MempoolEvent),
}

/// Represents different types of Bitcoin transaction destinations.
///
/// This enum defines various ways to specify where Bitcoin should be sent in a transaction,
/// supporting different address types and batch operations for efficient transaction construction.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Destination {
    /// Send to a Bitcoin address string.
    ///
    /// This variant accepts any valid Bitcoin address as a string and the amount to send.
    /// The address can be of any supported type (legacy, SegWit, Taproot, etc.).
    ///
    /// # Parameters
    /// * `String` - The Bitcoin address as a string (e.g., "bc1q...", "1A1z...", "bc1p...")
    /// * `u64` - Amount to send in satoshis
    Address(String, u64),

    /// Send to a Pay-to-Witness-Public-Key-Hash (P2WPKH) address.
    ///
    /// This variant creates a P2WPKH destination directly from a public key, which is
    /// more efficient than using the Address variant when you have the raw public key.
    /// P2WPKH provides better security and lower fees compared to legacy addresses.
    ///
    /// # Parameters
    /// * `PublicKey` - The secp256k1 public key to send to
    /// * `u64` - Amount to send in satoshis
    P2WPKH(PublicKey, u64),

    /// Send to multiple destinations in a single transaction.
    ///
    /// This variant allows batching multiple destinations into a single transaction,
    /// which is more efficient than creating separate transactions for each destination.
    /// All destinations in the batch will be included in the same transaction output.
    ///
    /// # Parameters
    /// * `Vec<Destination>` - Vector of destination objects to include in the batch
    Batch(Vec<Destination>),

    /// Send to a Pay-to-Taproot (P2TR) address.
    ///
    /// This variant creates a P2TR destination from an x-only public key and optional
    /// tap leaves (scripts). P2TR is the most advanced Bitcoin address type, providing
    /// enhanced privacy and efficiency through Taproot functionality.
    ///
    /// # Parameters
    /// * `XOnlyPublicKey` - The x-only public key (32 bytes) for the Taproot output
    /// * `Vec<ProtocolScript>` - Optional tap leaves (scripts) to include in the Taproot tree
    /// * `u64` - Amount to send in satoshis
    P2TR(XOnlyPublicKey, Vec<ProtocolScript>, u64),
}
