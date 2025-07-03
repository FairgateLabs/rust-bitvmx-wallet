# rust-bitvmx-wallet

A simple Bitcoin wallet CLI for the BitVMX project, built in Rust.  
This tool allows you to manage keys, fund and spend from addresses, and interact with a regtest Bitcoin node.

---

## Features

- Create and import secret keys (per wallet identifier)
- Add and remove funding (UTXOs)
- Fund addresses and manage transfers
- List wallet funds
- Mine regtest blocks
- Convert BTC to Satoshis
- Configurable via YAML config file

---

## How it works

- **rust-bitvmx-wallet** manages "logical wallets" (identifiers and keys) in a local database, but all Bitcoin transactions are performed using a single wallet loaded in your Bitcoin Core node.
- The Bitcoin Core wallet must be created and loaded in your node before using this CLI.  
  Example:
  ```sh
  docker exec -it bitvmx-node-1 bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword createwallet test_wallet
  ```
- The CLI stores key material and metadata in local files (see `config/regtest.yaml` for paths).

---

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
  Fund an identifier using regtest coins (only works if your node is in regtest mode).

- `btc-to-sat <BTC>`  
  Convert BTC to Satoshis.

- `list-wallets`  
  List all wallet identifiers and their public keys.

---

## Example workflow

```sh
# 1. Ensure your Bitcoin Core node is running and the wallet exists and is loaded:
docker exec -it bitvmx-node-1 bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword createwallet test_wallet

# 2. Create a logical wallet (generates a new keypair)
cargo run -- create-wallet alice

# 3. Fund the wallet in regtest mode
cargo run -- regtest-fund alice fund1 100000

# 4. List funds
cargo run -- list-funds alice

# 5. Send funds to another public key
cargo run -- fund-address alice fund1 <pubkey> 50000 1000

# 6. Mine blocks to confirm
cargo run -- mine 1
```

---

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
```

---

## Key Management Notes

- **Regtest:**  
  Use `create-wallet` to generate new keys and addresses for testing and mining.

- **Testnet/Mainnet:**  
  Use `import-key` to import an existing secret key (WIF format) that controls funds on a P2WPKH (bech32) address.  
  After importing, use `add-funding` to register the UTXO (by txid:vout and amount) that you control with this key.

---

## Important

- The Bitcoin Core wallet specified in your config **must exist and be loaded** in your node.
- All Bitcoin transactions are performed using this wallet; the CLI manages logical wallets/keys on top of it.
- Local wallet/key data is stored in the paths specified in your config file.

---

## License

MIT