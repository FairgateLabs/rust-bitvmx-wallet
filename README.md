# BitVMX Wallet

A comprehensive Bitcoin wallet implementation built with Rust, designed for the BitVMX ecosystem. This crate provides a full-featured wallet with support for multiple key management strategies, transaction handling, and Bitcoin network integration.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

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
cargo test -- --ignored --test-threads=1  
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

## Quick Start

```rust
use bitvmx_wallet::{config::Config, wallet::Wallet, wallet_manager::WalletManager};

// Load configuration
let config = Config::new(/* ... */)?;

// Create wallet manager
let wallet_manager = WalletManager::new(config)?;

// Create a new wallet (single descriptor wallet)
// Note: This creates a wallet without change descriptors, which limits functionality
let wallet = wallet_manager.create_new_wallet("my_wallet")?;
```

## Examples

See the individual module documentation for detailed examples of each component.

## License

This project is licensed under the MIT License.