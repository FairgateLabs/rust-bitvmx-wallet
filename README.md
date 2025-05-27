# rust-bitvmx-wallet

A simple Bitcoin wallet CLI for the BitVMX project, built in Rust.  
This tool allows you to manage keys, fund and spend from addresses, and interact with a regtest Bitcoin node.

## Features

- Create and import secret keys
- Add and remove funding (UTXOs)
- Fund addresses and manage transfers
- List wallet funds
- Mine regtest blocks
- Convert BTC to Satoshis
- Configurable via YAML config file

## Usage

```sh
cargo run -- [OPTIONS] <COMMAND>
```

### Global Options

- `-c, --config <FILE>`: Path to the config file (default: `config/regtest.yaml`)

### Commands

- `create-key <IDENTIFIER> <INDEX>`  
  Create a new secret key.

- `import-key <IDENTIFIER> <SECRET_KEY>`  
  Import a secret key.

- `add-funding <IDENTIFIER> <FUNDING_ID> <OUTPOINT> <AMOUNT>`  
  Add a UTXO as funding.

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
  Fund an identifier using regtest coins.

- `btc-to-sat <BTC>`  
  Convert BTC to Satoshis.

- `list-wallets`  
  List all wallet identifiers and their public keys.


## Example

```sh
cargo run -- create-key alice 0
cargo run -- add-funding alice fund1 "txid:vout" 100000
cargo run -- fund-address alice fund1 <pubkey> 50000 1000
cargo run -- list-funds alice
```

## Configuration

The wallet expects a YAML config file (default: `config/regtest.yaml`).  
You can specify a different config file with `-c` or `--config`.

## Key Management Notes

- **Regtest:**  
  You can use the `create-key` command to generate new keys and addresses for testing and mining.

- **Testnet/Mainnet:**  
  The recommended workflow is to use the `import-key` command to import an existing secret key (WIF format) that controls funds on a P2WPKH (bech32) address.  
  After importing, use `add-funding` to register the UTXO (by txid:vout and amount) that you control with this key.

## License

MIT
