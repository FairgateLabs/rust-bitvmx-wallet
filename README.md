# BitVMX Wallet

A comprehensive Bitcoin wallet implementation built with Rust, designed for the BitVMX ecosystem. This crate provides a full-featured wallet with support for multiple key management strategies, transaction handling, and Bitcoin network integration.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Table of Contents

- [Features](#features)
- [Test](#test)
- [Quick Start](#quick-start)
- [Examples](#examples)
  - [Basic Wallet Operations](#basic-wallet-operations)
  - [Advanced Transaction Destinations](#advanced-transaction-destinations)
  - [Regtest Development](#regtest-development)
  - [Creating Transactions Without Broadcasting](#creating-transactions-without-broadcasting)
  - [Creating Wallets with Different Methods](#creating-wallets-with-different-methods)
- [Documentation](#documentation)
- [License](#license)
- [BitVMX Ecosystem](#part-of-the-bitvmx-ecosystem)
- [Glossary](#glossary)

## Features

- **Multiple Key Management**: Support for private keys, derived keypairs, and partial private keys
- **Transaction Operations**: Send, receive, and manage Bitcoin transactions
- **Network Integration**: Full integration with Bitcoin Core RPC for blockchain synchronization
- **Regtest Support**: Comprehensive testing utilities for development and testing
- **CLI Interface**: Command-line interface for wallet operations
- **Persistent Storage**: SQLite-based wallet persistence

## Test

To run test use:

```sh
bash test.sh
```

## Quick Start

This example shows how to create a wallet and send funds. The Bitcoin RPC URL, wallet private key, and change private key are configured in the `config/regtest.yaml` file, though there are other ways to load them programmatically.
We need to sync the wallet to know the funds it has, and keep syncing it to have the latest information. We can set in the configuration file the start block to sync from so we don't need to sync the whole blockchain, only from when our wallet started having activity.
The wallet uses SQLite database to store transactions and UTXO information, but not the private keys (they are not stored anywhere). The database path is configured in the config file.
The `send_funds` method creates, signs, and broadcasts the transaction to the Bitcoin network via the RPC client.

```rust
use bitvmx_wallet::{
    config::Config,
    wallet::Wallet,
    wallet_manager::WalletManager
};
use bitvmx_wallet::wallet::types::Destination;

// Load configuration from YAML file
let config = bitvmx_settings::settings::load_config_file::<Config>(Some(
    "config/regtest.yaml".to_string()
))?;

// Create wallet with both receive and change descriptors from config
let mut wallet = Wallet::from_config(
    config.bitcoin,
    config.wallet,
)?;

// Sync wallet with blockchain
wallet.sync_wallet()?;

// Send funds to an address
let tx = wallet.send_funds(
    Destination::Address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), 100000), // 0.001 BTC
    Some(5), // 5 sat/vB fee rate
)?;
println!("Transaction sent: {}", tx.compute_txid());
```

## Examples

### Basic Wallet Operations

```rust
// Sync wallet with blockchain
wallet.sync_wallet()?;

// Get wallet balance
let balance = wallet.balance();
println!("Confirmed: {} sats", balance.confirmed); // Funds confirmed in blockchain
println!("Unconfirmed: {} sats", balance.unconfirmed); // Funds in mempool, not yet confirmed
println!("Trusted pending: {} sats", balance.trusted_pending); // Unconfirmed funds from our own transactions

// Generate a receiving address (address to deposit funds into the wallet)
let receive_address = wallet.receive_address()?;
println!("Receive address: {}", receive_address);

// List unspent transaction outputs (UTXOs)
let unspent_outputs = wallet.list_unspent()?;
println!("Number of UTXOs: {}", unspent_outputs.len());
for (i, output) in unspent_outputs.iter().enumerate() {
    println!("UTXO {}: {} sats", i, output.txout.value);
}

// Generate a change address (address where change is sent when spending)
// Note: Change addresses are automatically generated when creating transactions
// You can see them in the transaction outputs when you send funds
```

### Advanced Transaction Destinations

```rust
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvmx_wallet::wallet::types::Destination;
use protocol_builder::scripts::ProtocolScript;

// Send to multiple addresses in one transaction (batch)
let batch = vec![
    Destination::Address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), 50000),
    Destination::Address("bc1qdef456...".to_string(), 25000),
];
let tx = wallet.send_funds(Destination::Batch(batch), None)?;

// Send to a SegWit (P2WPKH) address from public key
let pubkey = PublicKey::from_str("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")?;
let tx = wallet.send_funds(Destination::P2WPKH(pubkey, 75000), Some(3))?;

// Send to a Taproot (P2TR) address from x-only public key
let x_pubkey = XOnlyPublicKey::from_str("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")?;
let tap_leaves = vec![]; // Optional tap leaves for script paths
let tx = wallet.send_funds(Destination::P2TR(x_pubkey, tap_leaves, 100000), Some(5))?;

// All destination types can be used directly or combined in batches
let mixed_batch = vec![
    Destination::Address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), 30000),
    Destination::P2WPKH(pubkey, 40000),
    Destination::P2TR(x_pubkey, tap_leaves, 50000),
];
let tx = wallet.send_funds(Destination::Batch(mixed_batch), None)?;
```

### Regtest Development

```rust
use bitvmx_wallet::RegtestWallet; // Trait that adds extra functionality intended for regtest only

// Fund wallet with test Bitcoin (regtest only)
wallet.fund()?; // Adds 150 BTC to wallet

// Send funds to a specific destination and mines 1 block
let tx = wallet.fund_destination(
    Destination::Address("bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), 100000)
)?;

// Mine blocks to confirm transactions
wallet.mine(6)?; // Mine 6 blocks
```

### Creating Transactions Without Broadcasting

```rust
use bitvmx_wallet::wallet::types::Destination;

// Create a transaction without broadcasting it
let tx = wallet.create_tx(
    Destination::Address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), 50000),
    Some(5), // 5 sat/vB fee rate
)?;

println!("Transaction created: {}", tx.compute_txid());
println!("Transaction is signed but not broadcast to the network");

// You can manually broadcast the transaction later if needed
let txid = wallet.send_transaction(&tx)?;
println!("Transaction broadcasted: {}", txid);

// Or you can inspect the transaction before broadcasting
println!("Transaction inputs: {}", tx.input.len());
println!("Transaction outputs: {}", tx.output.len());
```

### Creating Wallets with Different Methods

#### From Private Key

```rust
use bitvmx_wallet::wallet::Wallet;
use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;

let bitcoin_config = RpcConfig {
    url: "http://localhost:18443".to_string(),
    username: "foo".to_string(),
    password: "rpcpassword".to_string(),
    network: bitcoin::Network::Regtest,
};

let wallet_config = WalletConfig::new(
    "/tmp/wallet.db".to_string(),
    None, // start_height - start from genesis block
    None, // receive_key - will be provided directly to from_private_key
    None, // change_key - will be provided directly to from_private_key
)?;

// Create wallet with both receive and change private keys
let mut wallet = Wallet::from_private_key(
    bitcoin_config,
    wallet_config,
    "L4rK1yDtCWekvXuE6oXD9jCYgFNVs3VqHcVfJ9LRZdamizmv6Q6o", // receive key
    Some("KxJk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8Jk8"), // change key
)?;
```

#### From Derived Keypair

```rust
use bitvmx_wallet::wallet::Wallet;
use key_manager::key_manager::KeyManager;
use key_manager::key_type::BitcoinKeyType;

// Assuming you have a key_manager instance
let wallet = Wallet::from_derive_keypair(
    bitcoin_config,
    wallet_config,
    key_manager,
    BitcoinKeyType::P2tr, // Key type (P2tr, P2wpkh, etc.)
    0, // Use index 0 for the main key
    Some(1), // Use index 1 for change addresses (must be different from main key)
)?;
```

#### From Key Manager

```rust
use bitvmx_wallet::wallet::Wallet;
use key_manager::key_manager::KeyManager;
use bitcoin::PublicKey;

// Assuming you have a key_manager instance and public keys
let receive_pubkey = PublicKey::from_str("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")?;
let change_pubkey = PublicKey::from_str("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")?;

let wallet = Wallet::from_key_manager(
    bitcoin_config,
    wallet_config,
    key_manager,
    &receive_pubkey,
    Some(&change_pubkey),
)?;
```

## Documentation

This project includes comprehensive documentation that can be generated using `cargo doc`. The documentation covers all public APIs, structs, enums, and methods with detailed examples and usage instructions.

### Generating Documentation

To generate the documentation:

```bash
# Generate documentation for the current crate only
cargo doc --no-deps

# Generate documentation including dependencies
cargo doc

# Generate documentation and open in browser
cargo doc --open
```

The generated documentation will be available in `target/doc/bitvmx_wallet/index.html`.

### Documentation Features

The documentation includes:

- **Module-level documentation**: Overview of each module's purpose and functionality
- **Struct and enum documentation**: Detailed descriptions of all public types
- **Method documentation**: Comprehensive documentation for all public methods including:
  - Parameter descriptions
  - Return value explanations
  - Usage examples
  - Error handling information
- **Code examples**: Runnable examples showing how to use the API
- **Cross-references**: Links between related types and methods

### Key Documentation Sections

- **Configuration Management**: How to configure the wallet system
- **Wallet Operations**: Creating, loading, and managing wallets
- **Transaction Handling**: Sending and receiving Bitcoin transactions
- **Blockchain Synchronization**: Syncing with Bitcoin nodes
- **CLI Usage**: Command-line interface documentation
- **Error Handling**: Understanding and handling errors

## Glossary

### Bitcoin Terms

**Address**: A string that represents a destination for Bitcoin payments. Common types include:

- **Legacy (P2PKH)**: Addresses starting with "1" (e.g., `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`)
- **SegWit (P2WPKH)**: Addresses starting with "bc1" (e.g., `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`)
- **Taproot (P2TR)**: Addresses starting with "bc1p" (e.g., `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`)

**UTXO (Unspent Transaction Output)**: The fundamental unit of Bitcoin value. Each UTXO represents a specific amount of Bitcoin that can be spent as an input to a new transaction.

**Change Address**: An address where excess Bitcoin from a transaction is sent back to the sender. Used to return "change" when the input amount exceeds the desired output amount.

**Fee Rate**: The amount of Bitcoin paid per virtual byte of transaction data, typically measured in satoshis per virtual byte (sat/vB).

**Confirmation**: The number of blocks that have been mined on top of the block containing a transaction. More confirmations mean higher security.

### Wallet Terms

**Descriptor**: A string that describes how to derive Bitcoin addresses and private keys. Examples:

- **P2WPKH**: `wpkh(private_key)` - Pay-to-Witness-Public-Key-Hash
- **P2TR**: `tr(private_key)` - Pay-to-Taproot

**Key Manager**: A component that securely stores and manages cryptographic keys, including private keys, public keys, and derived keypairs.

**Wallet Sync**: The process of downloading and processing blockchain data to determine the wallet's current balance and transaction history.

**Change Descriptor**: A descriptor used to generate change addresses. Wallets with change descriptors can spend trusted unconfirmed UTXOs.

### Balance Types

**Confirmed Balance**: Bitcoin that has been confirmed in the blockchain and is safe to spend.

**Unconfirmed Balance**: Bitcoin from transactions in the mempool that haven't been confirmed yet.

**Trusted Pending**: Unconfirmed Bitcoin from transactions created by this wallet (considered safe to spend).

### Transaction Types

**P2WPKH (Pay-to-Witness-Public-Key-Hash)**: A SegWit transaction type that provides better security and lower fees than legacy transactions.

**P2TR (Pay-to-Taproot)**: The most advanced Bitcoin transaction type that offers enhanced privacy and efficiency through Taproot functionality.

**Batch Transaction**: A single transaction that sends Bitcoin to multiple recipients, reducing fees compared to multiple separate transactions.

### Network Types

**Mainnet**: The production Bitcoin network where real Bitcoin is used.

**Testnet**: A testing network that uses test Bitcoin with no real value.

**Regtest**: A local testing network that allows instant block generation and is used for development and testing.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
