# rust-bitvmx-wallet

A simple Bitcoin wallet CLI for the BitVMX project, built in Rust.  
This tool allows you to manage keys, fund and spend from addresses, and interact with a Bitcoin node (regtest, testnet, or mainnet).

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Features

- Create and import secret keys (per wallet identifier)
- Add and remove funding (UTXOs)
- Fund addresses and manage transfers
- List wallet funds
- Mine regtest blocks
- Convert BTC to Satoshis
- Configurable via YAML config file

## How it works

- **rust-bitvmx-wallet** manages "logical wallets" (identifiers and keys) in a local database.
- All Bitcoin transactions (except the initial regtest funding helper) are constructed and signed by this CLI, not by the Bitcoin Core wallet.
- For **regtest only**: if you use the `regtest-fund` helper, the wallet name in your config must match an existing wallet in your node.

## Test

To run test use:

```sh
cargo test -- --ignored --test-threads=1  
```

## Usage

```sh
cargo run -- [OPTIONS] <COMMAND>
```

### Global Options

- `-c, --config <FILE>`: Path to the config file (default: `config/regtest.yaml`)

### Commands

- `create-wallet <IDENTIFIER>`  
  Create a new logical wallet (generates a new keypair and stores it locally).

- `import-key <IDENTIFIER> <SECRET_KEY>`  
  Import a secret key (hex or WIF) for an identifier.

- `export-wallet <IDENTIFIER>`  
  Export the public and secret key for a wallet.

- `add-funding <IDENTIFIER> <FUNDING_ID> <OUTPOINT> <AMOUNT>`  
  Register a UTXO as funding (OUTPOINT format: `"txid:vout"`).

- `remove-funding <IDENTIFIER> <FUNDING_ID>`  
  Remove a funding entry.

- `fund-address <IDENTIFIER> <FUNDING_ID> <TO_PUBKEY> <AMOUNT> <FEE> {OUTPUT_IS_TAPROOT = FALSE}`  
  Send funds to a public key.

- `confirm-transfer <IDENTIFIER> <FUNDING_ID>`  
  Confirm a pending transfer.

- `revert-transfer <IDENTIFIER> <FUNDING_ID>`  
  Revert a pending transfer.

- `list-funds <IDENTIFIER>`  
  List all funds for an identifier.

- `mine <NUM_BLOCKS>`  
  Mine blocks (regtest only).

- `regtest-fund <IDENTIFIER> <FUNDING_ID> <AMOUNT>`  
  Fund an identifier using regtest coins (only works if your node is in regtest mode and the wallet name matches).

- `btc-to-sat <BTC>`  
  Convert BTC to Satoshis.

- `list-wallets`  
  List all wallet identifiers and their public keys.

## Example workflow

```sh
# 1. (Regtest only, optional) Ensure your Bitcoin Core node has a wallet matching your config:
docker exec -it bitvmx-node-1 bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword createwallet test_wallet

# 2. Create a logical wallet (generates a new keypair)
cargo run -- create-wallet alice

# 3. Fund the wallet in regtest mode (helper)
cargo run -- regtest-fund alice

# 4. List funds
cargo run -- list-funds alice

# 5. Send funds to another address
cargo run -- send-and-mine alice bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw  1000

```

## Configuration

The wallet expects a YAML config file (default: `config/regtest.yaml`).  
You can specify a different config file with `-c` or `--config`.

Example `config/regtest.yaml`:

```yaml
bitcoin:
  network: regtest
  url: http://127.0.0.1:18443
  username: foo
  password: rpcpassword
  wallet: test_wallet

key_manager:
  network: regtest

key_storage:
  password: secret_password_1
  path: /tmp/regtest/wallet/keys.db

storage:
  path: /tmp/regtest/wallet/storage.db

wallet:
  db_path: /tmp/regtest/wallet/wallet.db
  start_height: 0
```

## Key Management Notes

- **Regtest:**  
  Use `create-wallet` to generate new keys and addresses for testing and mining.

- **Testnet/Mainnet:**  
  Use `import-key` to import an existing secret key (WIF format) that controls funds on a P2WPKH (bech32) address.  
  After importing, use `sync-wallet` to update balance and spendable utxos that you control with this key.

## Important

- For regtest, if you use the `regtest-fund` helper, it will mint 103 blocks to send 150 BTC to the funded wallet.
- All transactions are constructed and signed by this CLI, not by the Bitcoin Core wallet.
- Local wallet/key data is stored in the paths specified in your config file.
- Local wallet transactions data is stored under `/tmp/wallet_manager/` folder.

## License

MIT

## References

- [Descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#examples)
- [Bdk Wallet](https://docs.rs/bdk_wallet/latest/bdk_wallet/index.html)
- [Tx Builder](https://docs.rs/bdk_wallet/2.0.0/bdk_wallet/struct.TxBuilder.html#method.finish)
- [Example wallet rpc](https://github.com/bitcoindevkit/bdk_wallet/blob/master/examples/example_wallet_rpc/src/main.rs)