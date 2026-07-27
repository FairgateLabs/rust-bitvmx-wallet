//! The regtest-only wallet helpers must refuse to run against a simchain simnet.
//!
//! Simchain's *encoding* is regtest, so `check_network`'s `bitcoin_network()` test
//! waves it through. But its blocks are produced externally and its user-facing node
//! runs with `-disablewallet` — and `generatetoaddress` is a *mining* RPC, not a wallet
//! one, so that node would happily serve `mine()` and silently produce a real block on
//! a chain that is supposed to be mining itself.
//!
//! These tests need no Bitcoin node: `check_network` inspects local state only, and
//! wallet construction does not open a connection.

use anyhow::Result;
use bitcoin::Network;
use bitvmx_bitcoin_rpc::rpc_config::{NetworkFlavor, RpcConfig};
use bitvmx_wallet::wallet::{config::WalletConfig, errors::WalletError, RegtestWallet, Wallet};

const RECEIVE_KEY: &str = "cQ5J65TDnDi1ox8AVkWkEnxByhr4yRyjToqEDVeNnhNSKtfPWzW3";
const CHANGE_KEY: &str = "cVaWhDZjBJFBuBP31UGaCMVP1jJG7XWXDPEacybyUbjYeeVhPCWc";

fn wallet_for(flavor: NetworkFlavor, tag: &str) -> Result<Wallet> {
    let bitcoin = RpcConfig::new(
        flavor,
        "http://127.0.0.1:18443".to_string(),
        "foo".to_string(),
        "rpcpassword".to_string(),
        "test_wallet".to_string(),
    );
    let wallet_config = WalletConfig::new(
        format!("/tmp/simchain_guard_test/{tag}/wallet.db"),
        Some(0),
        Some(RECEIVE_KEY.to_string()),
        Some(CHANGE_KEY.to_string()),
    )?;
    let _ = Wallet::clear_db(&wallet_config);
    Ok(Wallet::from_config(bitcoin, wallet_config)?)
}

#[test]
fn simchain_is_rejected_by_check_network() -> Result<()> {
    let wallet = wallet_for(NetworkFlavor::Simchain, "simchain")?;

    // It really is regtest as far as encoding goes...
    assert_eq!(wallet.network, Network::Regtest);
    // ...but it is not regtest, and the regtest-only helpers must refuse.
    let err = wallet.check_network().unwrap_err();
    assert!(
        matches!(err, WalletError::NotAllowedOnSimchain),
        "expected NotAllowedOnSimchain, got {err:?}"
    );
    Ok(())
}

#[test]
fn simchain_rejection_is_distinct_from_wrong_network() -> Result<()> {
    // Simchain is not a misconfigured network, so it must not report RegtestOnly:
    // that would send someone hunting for a wrong `network:` field in their YAML.
    let simchain = wallet_for(NetworkFlavor::Simchain, "distinct_sim")?;
    let testnet = wallet_for(NetworkFlavor::Testnet, "distinct_test")?;

    assert!(matches!(
        simchain.check_network().unwrap_err(),
        WalletError::NotAllowedOnSimchain
    ));
    assert!(matches!(
        testnet.check_network().unwrap_err(),
        WalletError::RegtestOnly
    ));
    Ok(())
}

#[test]
fn plain_regtest_still_passes_check_network() -> Result<()> {
    // Regression gate: the guard is additive and must not break plain regtest, which
    // legitimately mines and funds through the node wallet.
    let wallet = wallet_for(NetworkFlavor::Regtest, "regtest")?;
    assert_eq!(wallet.network, Network::Regtest);
    assert!(wallet.check_network().is_ok());
    Ok(())
}

#[test]
fn regtest_only_helpers_all_refuse_on_simchain() -> Result<()> {
    // Every entry point that goes through check_network, so a future helper that
    // forgets the check shows up as a gap here.
    let mut wallet = wallet_for(NetworkFlavor::Simchain, "helpers")?;

    let address = wallet.receive_address()?.to_string();

    assert!(wallet.mine(1).is_err(), "mine must refuse");
    assert!(
        wallet.mine_to_address(1, &address).is_err(),
        "mine_to_address must refuse"
    );
    assert!(wallet.fund().is_err(), "fund must refuse");
    Ok(())
}

#[test]
fn simchain_and_regtest_wallets_are_distinguishable() -> Result<()> {
    // The bug this exists to prevent: two chains that share an encoding but not a
    // capability set must not be interchangeable. The flavor is private, so the
    // difference is only observable through behavior — which is the point.
    let simchain = wallet_for(NetworkFlavor::Simchain, "cmp_sim")?;
    let regtest = wallet_for(NetworkFlavor::Regtest, "cmp_reg")?;

    // Identical encoding...
    assert_eq!(simchain.network, regtest.network);
    assert_eq!(simchain.network, Network::Regtest);
    // ...opposite capabilities.
    assert!(simchain.check_network().is_err());
    assert!(regtest.check_network().is_ok());
    Ok(())
}
