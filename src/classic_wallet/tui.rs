use super::{classic_wallet::ClassicWallet, errors::ClassicWalletError};
use bitcoin::{Amount, OutPoint, PublicKey, Txid};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use key_manager::key_type::BitcoinKeyType;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};
use std::{collections::HashMap, io, rc::Rc, str::FromStr, time::Duration};

const NAME_COLUMN_WIDTH: usize = 10;
const SATS_COLUMN_WIDTH: usize = 9;

struct WalletItem {
    name: String,
    pubkey: String,
    address: String,
}

#[derive(Clone)]
struct FundItem {
    funding_id: String,
    outpoint: OutPoint,
    amount: u64,
    pending: Option<PendingTransferItem>,
}

#[derive(Clone)]
struct PendingTransferItem {
    txid: Txid,
    change_vout: u32,
    change_amount: u64,
}

enum View {
    WalletList,
    WalletDetails,
    CreateWallet,
    ImportWalletName,
    ImportWalletPrivateKey,
    AddFundingName,
    AddFundingOutpoint,
    AddFundingAmount,
    TransferDestination,
    TransferAmount,
    TransferFee,
    ConfirmTransferDetails,
    JoinFundsFee,
    ConfirmJoinFunds,
    RegtestFundName,
    RegtestFundAmount,
    ConfirmDeleteWallet,
    ConfirmDeleteFund,
    ShowPrivateKey,
    ShowLink,
}

struct App {
    status: String,
    wallets: Vec<WalletItem>,
    selected_wallet: usize,
    view: View,
    funds: Vec<FundItem>,
    selected_fund: usize,
    input: String,
    import_wallet_name: String,
    private_key: String,
    add_funding_id: String,
    add_outpoint: String,
    transfer_destination: String,
    transfer_amount: u64,
    transfer_fee: u64,
    join_fee_per_input: u64,
    is_regtest: bool,
    is_testnet: bool,
    link: String,
}

impl App {
    fn new(wallet: &ClassicWallet) -> Self {
        let mut app = Self {
            status: "Press ↑/↓ to select, Enter for details, c to create, i to import, d to delete, p for private key, l for link, q/Esc to quit"
                .to_string(),
            wallets: Vec::new(),
            selected_wallet: 0,
            view: View::WalletList,
            funds: Vec::new(),
            selected_fund: 0,
            input: String::new(),
            import_wallet_name: String::new(),
            private_key: String::new(),
            add_funding_id: String::new(),
            add_outpoint: String::new(),
            transfer_destination: String::new(),
            transfer_amount: 0,
            transfer_fee: 0,
            join_fee_per_input: 0,
            is_regtest: wallet.is_regtest(),
            is_testnet: wallet.is_testnet(),
            link: String::new(),
        };
        app.refresh_wallets(wallet);
        app
    }

    fn refresh_wallets(&mut self, wallet: &ClassicWallet) {
        match wallet.get_wallets() {
            Ok(wallets) => {
                self.wallets = wallets
                    .into_iter()
                    .map(|(name, pubkey)| WalletItem {
                        name,
                        address: wallet
                            .public_key_to_bech32_address(&pubkey)
                            .map(|address| address.to_string())
                            .unwrap_or_else(|e| format!("unavailable: {e}")),
                        pubkey: pubkey.to_string(),
                    })
                    .collect();

                if self.wallets.is_empty() {
                    self.selected_wallet = 0;
                    self.status = "No wallets found".to_string();
                } else {
                    self.selected_wallet = self.selected_wallet.min(self.wallets.len() - 1);
                    self.status = "Wallet list refreshed".to_string();
                }
            }
            Err(e) => {
                self.wallets.clear();
                self.selected_wallet = 0;
                self.status = format!("Failed to load wallets: {e}");
            }
        }
    }

    fn selected_wallet(&self) -> Option<&WalletItem> {
        self.wallets.get(self.selected_wallet)
    }

    fn select_previous(&mut self) {
        if self.wallets.is_empty() {
            return;
        }

        if self.selected_wallet == 0 {
            self.selected_wallet = self.wallets.len() - 1;
        } else {
            self.selected_wallet -= 1;
        }
    }

    fn select_next(&mut self) {
        if self.wallets.is_empty() {
            return;
        }

        self.selected_wallet = (self.selected_wallet + 1) % self.wallets.len();
    }

    fn selected_fund(&self) -> Option<&FundItem> {
        self.funds.get(self.selected_fund)
    }

    fn select_previous_fund(&mut self) {
        if self.funds.is_empty() {
            return;
        }

        if self.selected_fund == 0 {
            self.selected_fund = self.funds.len() - 1;
        } else {
            self.selected_fund -= 1;
        }
    }

    fn select_next_fund(&mut self) {
        if self.funds.is_empty() {
            return;
        }

        self.selected_fund = (self.selected_fund + 1) % self.funds.len();
    }

    fn open_selected_wallet(&mut self, wallet: &ClassicWallet) {
        let Some(selected_wallet) = self.selected_wallet() else {
            self.status = "No wallet selected".to_string();
            return;
        };

        match wallet.list_funds(&selected_wallet.name) {
            Ok(funds) => {
                let wallet_name = selected_wallet.name.clone();
                let pending = match wallet.list_pending_transfers(&wallet_name) {
                    Ok(pending) => pending
                        .into_iter()
                        .map(|p| {
                            (
                                p.funding_id,
                                PendingTransferItem {
                                    txid: p.txid,
                                    change_vout: p.change_vout,
                                    change_amount: p.change_amount_sat,
                                },
                            )
                        })
                        .collect::<HashMap<_, _>>(),
                    Err(e) => {
                        self.status =
                            format!("Loaded funds, but failed to load pending transfers: {e}");
                        HashMap::new()
                    }
                };
                let total = funds.iter().map(|(_, _, amount)| amount).sum::<u64>();
                self.funds = funds
                    .into_iter()
                    .map(|(funding_id, outpoint, amount)| {
                        let pending = pending.get(&funding_id).cloned();
                        FundItem {
                            funding_id,
                            outpoint,
                            amount,
                            pending,
                        }
                    })
                    .collect();
                self.selected_fund = self.selected_fund.min(self.funds.len().saturating_sub(1));
                self.view = View::WalletDetails;
                self.status = format!(
                    "{wallet_name}: {} funding entries, {total} sats total",
                    self.funds.len()
                );
            }
            Err(e) => {
                self.status = format!("Failed to load funds: {e}");
            }
        }
    }

    fn back_to_wallets(&mut self) {
        self.view = View::WalletList;
        self.funds.clear();
        self.input.clear();
        self.import_wallet_name.clear();
        self.private_key.clear();
        self.add_funding_id.clear();
        self.add_outpoint.clear();
        self.transfer_destination.clear();
        self.transfer_amount = 0;
        self.transfer_fee = 0;
        self.join_fee_per_input = 0;
        self.link.clear();
        self.status = "Back to wallet list".to_string();
    }

    fn start_create_wallet(&mut self) {
        self.input.clear();
        self.view = View::CreateWallet;
        self.status = "Enter a new wallet name".to_string();
    }

    fn create_wallet(&mut self, wallet: &ClassicWallet) {
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.status = "Wallet name cannot be empty".to_string();
            return;
        }

        match wallet.create_wallet(&name, BitcoinKeyType::P2wpkh) {
            Ok(pubkey) => {
                self.status = format!("Created wallet {name}: {pubkey}");
                self.input.clear();
                self.view = View::WalletList;
                self.refresh_wallets(wallet);
                if let Some(index) = self.wallets.iter().position(|wallet| wallet.name == name) {
                    self.selected_wallet = index;
                }
            }
            Err(e) => self.status = format!("Failed to create wallet: {e}"),
        }
    }

    fn start_import_wallet(&mut self) {
        self.input.clear();
        self.import_wallet_name.clear();
        self.view = View::ImportWalletName;
        self.status = "Enter wallet name for imported private key".to_string();
    }

    fn start_delete_wallet(&mut self) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };

        self.view = View::ConfirmDeleteWallet;
        self.status = format!("Delete wallet '{wallet_name}'? Press y to confirm or n to cancel");
    }

    fn show_private_key(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };

        match wallet.export_wallet(&wallet_name) {
            Ok((_, private_key)) => {
                self.private_key = private_key.to_string();
                self.view = View::ShowPrivateKey;
                self.status = format!("Showing private key for {wallet_name}");
            }
            Err(e) => self.status = format!("Failed to export private key: {e}"),
        }
    }

    fn show_selected_wallet_link(&mut self) {
        if !self.is_testnet {
            self.status = "Mempool links are only available on testnet".to_string();
            return;
        }

        let Some((wallet_name, address)) = self
            .selected_wallet()
            .map(|wallet| (wallet.name.clone(), wallet.address.clone()))
        else {
            self.status = "No wallet selected".to_string();
            return;
        };

        self.link = format!("https://mempool.space/testnet/address/{address}");
        self.view = View::ShowLink;
        self.status = format!("Mempool address link for {wallet_name}");
    }

    fn show_selected_fund_link(&mut self) {
        if !self.is_testnet {
            self.status = "Mempool links are only available on testnet".to_string();
            return;
        }

        let Some((funding_id, txid, vout)) = self.selected_fund().map(|fund| {
            (
                fund.funding_id.clone(),
                fund.outpoint.txid,
                fund.outpoint.vout,
            )
        }) else {
            self.status = "No funding entry selected".to_string();
            return;
        };

        self.link = format!("https://mempool.space/testnet/tx/{txid}#flow=&vout={vout}");
        self.view = View::ShowLink;
        self.status = format!("Mempool transaction output link for '{funding_id}'");
    }

    fn close_link(&mut self) {
        self.link.clear();
        self.view = if self.funds.is_empty() {
            View::WalletList
        } else {
            View::WalletDetails
        };
        self.status = "Closed link".to_string();
    }

    fn start_add_funding(&mut self) {
        if self.selected_wallet().is_none() {
            self.status = "No wallet selected".to_string();
            return;
        }

        self.input.clear();
        self.add_funding_id.clear();
        self.add_outpoint.clear();
        self.view = View::AddFundingName;
        self.status = "Enter a name for this funding entry".to_string();
    }

    fn accept_add_funding_name(&mut self) {
        let funding_id = self.input.trim().to_string();
        if funding_id.is_empty() {
            self.status = "Funding name cannot be empty".to_string();
            return;
        }

        self.add_funding_id = funding_id;
        self.input.clear();
        self.view = View::AddFundingOutpoint;
        self.status = "Enter outpoint as txid:vout".to_string();
    }

    fn accept_add_funding_outpoint(&mut self) {
        let outpoint = self.input.trim().to_string();
        if OutPoint::from_str(&outpoint).is_err() {
            self.status = "Invalid outpoint. Use txid:vout".to_string();
            return;
        }

        self.add_outpoint = outpoint;
        self.input.clear();
        self.view = View::AddFundingAmount;
        self.status = "Enter amount in sats, or press r to fetch it from Bitcoin RPC".to_string();
    }

    fn add_funding_with_manual_amount(&mut self, wallet: &ClassicWallet) {
        let amount = match self.input.trim().parse::<u64>() {
            Ok(amount) => amount,
            Err(_) => {
                self.status = "Invalid amount. Enter sats as a whole number".to_string();
                return;
            }
        };

        self.add_funding(wallet, Some(amount));
    }

    fn add_funding_from_rpc(&mut self, wallet: &ClassicWallet) {
        self.add_funding(wallet, None);
    }

    fn add_funding(&mut self, wallet: &ClassicWallet, amount: Option<u64>) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let outpoint = match OutPoint::from_str(&self.add_outpoint) {
            Ok(outpoint) => outpoint,
            Err(e) => {
                self.status = format!("Invalid outpoint: {e}");
                return;
            }
        };
        let funding_id = self.add_funding_id.clone();

        match wallet.add_funding_with_optional_amount(&wallet_name, &funding_id, outpoint, amount) {
            Ok(()) => {
                self.input.clear();
                self.add_funding_id.clear();
                self.add_outpoint.clear();
                self.open_selected_wallet(wallet);
                self.status = format!("Added funding '{funding_id}' to {wallet_name}");
            }
            Err(e) => self.status = format!("Failed to add funding: {e}"),
        }
    }

    fn cancel_add_funding(&mut self) {
        self.input.clear();
        self.add_funding_id.clear();
        self.add_outpoint.clear();
        self.view = View::WalletDetails;
        self.status = "Add funding cancelled".to_string();
    }

    fn start_delete_fund(&mut self) {
        let Some(fund) = self.selected_fund() else {
            self.status = "No funding entry selected".to_string();
            return;
        };
        if fund.pending.is_some() {
            self.status = "Cannot delete a funding entry with a pending transfer".to_string();
            return;
        }

        let funding_id = fund.funding_id.clone();
        self.view = View::ConfirmDeleteFund;
        self.status =
            format!("Delete funding entry '{funding_id}'? Press y to confirm or n to cancel");
    }

    fn cancel_delete_fund(&mut self) {
        self.view = View::WalletDetails;
        self.status = "Delete funding cancelled".to_string();
    }

    fn delete_selected_fund(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.view = View::WalletDetails;
            self.status = "No wallet selected".to_string();
            return;
        };
        let Some(funding_id) = self.selected_fund().map(|fund| fund.funding_id.clone()) else {
            self.view = View::WalletDetails;
            self.status = "No funding entry selected".to_string();
            return;
        };

        match wallet.remove_funding(&wallet_name, &funding_id) {
            Ok(()) => {
                self.open_selected_wallet(wallet);
                self.status = format!("Deleted funding entry '{funding_id}' from {wallet_name}");
            }
            Err(e) => self.status = format!("Failed to delete funding entry: {e}"),
        }
    }

    fn start_join_funds(&mut self) {
        if self.selected_wallet().is_none() {
            self.status = "No wallet selected".to_string();
            return;
        }
        if self.funds.is_empty() {
            self.status = "No funds available to join".to_string();
            return;
        }
        if self.funds.iter().any(|fund| fund.pending.is_some()) {
            self.status = "Confirm or revert pending transfers before joining funds".to_string();
            return;
        }

        self.input.clear();
        self.join_fee_per_input = 0;
        self.view = View::JoinFundsFee;
        self.status = "Enter fee per input in sats (minimum 500)".to_string();
    }

    fn accept_join_funds_fee(&mut self) {
        let fee_per_input = match self.input.trim().parse::<u64>() {
            Ok(fee) => fee,
            Err(_) => {
                self.status = "Invalid fee. Enter sats as a whole number".to_string();
                return;
            }
        };
        if fee_per_input < 500 {
            self.status = "Rejected: fee per input must be at least 500 sats".to_string();
            return;
        }
        let input_count = self.funds.len() as u64;
        let Some(total_fee) = fee_per_input.checked_mul(input_count) else {
            self.status = "Rejected: total fee overflows".to_string();
            return;
        };
        let total = self.funds.iter().map(|fund| fund.amount).sum::<u64>();
        if total_fee >= total {
            self.status = format!(
                "Rejected: total fee ({total_fee} sats) must be less than total funds ({total} sats)"
            );
            return;
        }

        self.join_fee_per_input = fee_per_input;
        self.input.clear();
        self.view = View::ConfirmJoinFunds;
        self.status = "Review join-funds details. Press y to send or n/Esc to cancel".to_string();
    }

    fn send_join_funds(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let input_count = self.funds.len() as u64;
        let Some(total_fee) = self.join_fee_per_input.checked_mul(input_count) else {
            self.status = "Rejected: total fee overflows".to_string();
            return;
        };
        let total = self.funds.iter().map(|fund| fund.amount).sum::<u64>();
        if input_count == 0 || self.join_fee_per_input < 500 || total_fee >= total {
            self.status = "Rejected: invalid join-funds parameters".to_string();
            return;
        }

        match wallet.join_funds(&wallet_name, self.join_fee_per_input, false) {
            Ok(txid) => {
                self.join_fee_per_input = 0;
                self.open_selected_wallet(wallet);
                self.status =
                    format!("Join-funds transaction sent, txid: {txid}. Pending confirmation");
            }
            Err(e) => self.status = format!("Failed to join funds: {e}"),
        }
    }

    fn cancel_join_funds(&mut self) {
        self.input.clear();
        self.join_fee_per_input = 0;
        self.view = View::WalletDetails;
        self.status = "Join-funds cancelled".to_string();
    }

    fn start_transfer(&mut self) {
        if self.selected_fund().is_none() {
            self.status = "No funding entry selected".to_string();
            return;
        }
        if self
            .selected_fund()
            .and_then(|fund| fund.pending.as_ref())
            .is_some()
        {
            self.status = "Selected funding entry already has a pending transfer".to_string();
            return;
        }

        self.input.clear();
        self.transfer_destination.clear();
        self.transfer_amount = 0;
        self.transfer_fee = 0;
        self.view = View::TransferDestination;
        self.status = "Enter destination public key".to_string();
    }

    fn accept_transfer_destination(&mut self) {
        let destination = self.input.trim().to_string();
        if PublicKey::from_str(&destination).is_err() {
            self.status = "Invalid destination public key".to_string();
            return;
        }

        self.transfer_destination = destination;
        self.input.clear();
        self.view = View::TransferAmount;
        self.status = "Enter amount in sats".to_string();
    }

    fn accept_transfer_amount(&mut self) {
        let amount = match self.input.trim().parse::<u64>() {
            Ok(amount) if amount > 0 => amount,
            _ => {
                self.status = "Invalid amount. Enter sats as a positive whole number".to_string();
                return;
            }
        };
        let available = self.selected_fund().map(|fund| fund.amount).unwrap_or(0);
        if amount > available {
            self.status = format!(
                "Rejected: amount is greater than selected funding entry balance ({available} sats)"
            );
            return;
        }

        self.transfer_amount = amount;
        self.input.clear();
        self.view = View::TransferFee;
        self.status = "Enter absolute tx fee in sats (minimum 500)".to_string();
    }

    fn accept_transfer_fee(&mut self) {
        let fee = match self.input.trim().parse::<u64>() {
            Ok(fee) => fee,
            Err(_) => {
                self.status = "Invalid fee. Enter sats as a whole number".to_string();
                return;
            }
        };
        if fee < 500 {
            self.status = "Rejected: tx fee must be at least 500 sats".to_string();
            return;
        }
        let available = self.selected_fund().map(|fund| fund.amount).unwrap_or(0);
        let Some(total_spend) = self.transfer_amount.checked_add(fee) else {
            self.status = "Rejected: amount plus fee overflows".to_string();
            return;
        };
        if total_spend > available {
            let max_amount = available.saturating_sub(fee);
            self.status = format!(
                "Rejected: amount plus fee exceeds available funds. Max amount with this fee is {max_amount} sats"
            );
            return;
        }

        self.transfer_fee = fee;
        self.input.clear();
        self.view = View::ConfirmTransferDetails;
        self.status = "Review transfer details. Press y to send or n/Esc to cancel".to_string();
    }

    fn send_transfer(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let Some(fund) = self.selected_fund().cloned() else {
            self.status = "No funding entry selected".to_string();
            return;
        };
        if self.transfer_fee < 500 {
            self.status = "Rejected: tx fee must be at least 500 sats".to_string();
            return;
        }
        let Some(total_spend) = self.transfer_amount.checked_add(self.transfer_fee) else {
            self.status = "Rejected: amount plus fee overflows".to_string();
            return;
        };
        if total_spend > fund.amount {
            let max_amount = fund.amount.saturating_sub(self.transfer_fee);
            self.status = format!(
                "Rejected: amount plus fee exceeds available funds. Max amount with this fee is {max_amount} sats"
            );
            return;
        }
        let to_pubkey = match PublicKey::from_str(&self.transfer_destination) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                self.status = format!("Invalid destination public key: {e}");
                return;
            }
        };

        match wallet.fund_address(
            &wallet_name,
            &fund.funding_id,
            to_pubkey,
            &vec![self.transfer_amount],
            self.transfer_fee,
            false,
            false,
            None,
        ) {
            Ok(txid) => {
                let funding_id = fund.funding_id;
                self.transfer_destination.clear();
                self.transfer_amount = 0;
                self.transfer_fee = 0;
                self.open_selected_wallet(wallet);
                self.status = format!(
                    "Transfer sent from '{funding_id}', txid: {txid}. Pending confirmation"
                );
            }
            Err(e) => self.status = format!("Failed to send transfer: {e}"),
        }
    }

    fn cancel_transfer(&mut self) {
        self.input.clear();
        self.transfer_destination.clear();
        self.transfer_amount = 0;
        self.transfer_fee = 0;
        self.view = View::WalletDetails;
        self.status = "Transfer cancelled".to_string();
    }

    fn confirm_selected_transfer(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let Some(funding_id) = self.selected_fund().map(|fund| fund.funding_id.clone()) else {
            self.status = "No funding entry selected".to_string();
            return;
        };

        match wallet.confirm_transfer(&wallet_name, &funding_id) {
            Ok(()) => {
                self.open_selected_wallet(wallet);
                self.status = format!("Confirmed pending transfer for '{funding_id}'");
            }
            Err(e) => self.status = format!("Failed to confirm transfer: {e}"),
        }
    }

    fn check_and_confirm_selected_transfer(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let Some(funding_id) = self.selected_fund().map(|fund| fund.funding_id.clone()) else {
            self.status = "No funding entry selected".to_string();
            return;
        };

        if self.is_regtest {
            if let Err(e) = wallet.mine(1) {
                self.status = format!("Failed to mine regtest block before checking transfer: {e}");
                return;
            }
        }

        match wallet.confirm_transfer_if_mined(&wallet_name, &funding_id) {
            Ok(true) => {
                self.open_selected_wallet(wallet);
                let prefix = if self.is_regtest {
                    "Mined 1 block. "
                } else {
                    ""
                };
                self.status =
                    format!("{prefix}Transfer for '{funding_id}' is mined and was confirmed");
            }
            Ok(false) => self.status = format!("Transfer for '{funding_id}' is not mined yet"),
            Err(e) => self.status = format!("Failed to check transfer: {e}"),
        }
    }

    fn start_regtest_fund(&mut self) {
        if !self.is_regtest {
            self.status = "Regtest funding is only available on regtest".to_string();
            return;
        }
        if self.selected_wallet().is_none() {
            self.status = "No wallet selected".to_string();
            return;
        }

        self.input.clear();
        self.add_funding_id.clear();
        self.view = View::RegtestFundName;
        self.status = "Enter a name for this regtest funding entry".to_string();
    }

    fn accept_regtest_fund_name(&mut self) {
        let funding_id = self.input.trim().to_string();
        if funding_id.is_empty() {
            self.status = "Funding name cannot be empty".to_string();
            return;
        }

        self.add_funding_id = funding_id;
        self.input.clear();
        self.view = View::RegtestFundAmount;
        self.status = "Enter wanted regtest funding amount in sats".to_string();
    }

    fn regtest_fund(&mut self, wallet: &ClassicWallet) {
        let Some(wallet_name) = self.selected_wallet().map(|wallet| wallet.name.clone()) else {
            self.status = "No wallet selected".to_string();
            return;
        };
        let amount = match self.input.trim().parse::<u64>() {
            Ok(amount) => amount,
            Err(_) => {
                self.status = "Invalid amount. Enter sats as a whole number".to_string();
                return;
            }
        };
        let funding_id = self.add_funding_id.clone();

        match wallet.regtest_fund(&wallet_name, &funding_id, amount) {
            Ok(()) => {
                self.input.clear();
                self.add_funding_id.clear();
                self.open_selected_wallet(wallet);
                self.status =
                    format!("Regtest funded {wallet_name} with {amount} sats as '{funding_id}'");
            }
            Err(e) => self.status = format!("Failed to regtest fund: {e}"),
        }
    }

    fn cancel_regtest_fund(&mut self) {
        self.input.clear();
        self.add_funding_id.clear();
        self.view = View::WalletDetails;
        self.status = "Regtest funding cancelled".to_string();
    }

    fn cancel_delete_wallet(&mut self) {
        self.view = View::WalletList;
        self.status = "Delete cancelled".to_string();
    }

    fn delete_selected_wallet(&mut self, wallet: &ClassicWallet) {
        let Some(selected_wallet) = self.selected_wallet() else {
            self.view = View::WalletList;
            self.status = "No wallet selected".to_string();
            return;
        };

        let name = selected_wallet.name.clone();
        match wallet.remove_wallet(&name) {
            Ok(()) => {
                self.view = View::WalletList;
                self.status = format!("Deleted wallet {name}");
                self.refresh_wallets(wallet);
            }
            Err(e) => self.status = format!("Failed to delete wallet: {e}"),
        }
    }

    fn accept_import_wallet_name(&mut self) {
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.status = "Wallet name cannot be empty".to_string();
            return;
        }

        self.import_wallet_name = name;
        self.input.clear();
        self.view = View::ImportWalletPrivateKey;
        self.status = "Enter private key/secret key".to_string();
    }

    fn import_wallet(&mut self, wallet: &ClassicWallet) {
        let private_key = self.input.trim().to_string();
        if private_key.is_empty() {
            self.status = "Private key cannot be empty".to_string();
            return;
        }

        let name = self.import_wallet_name.clone();
        match wallet.create_wallet_from_secret(&name, &private_key) {
            Ok(()) => {
                self.status = format!("Imported wallet {name}");
                self.input.clear();
                self.import_wallet_name.clear();
                self.view = View::WalletList;
                self.refresh_wallets(wallet);
                if let Some(index) = self.wallets.iter().position(|wallet| wallet.name == name) {
                    self.selected_wallet = index;
                }
            }
            Err(e) => self.status = format!("Failed to import wallet: {e}"),
        }
    }

    fn handle_text_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(ch) => self.input.push(ch),
            KeyCode::Backspace => {
                self.input.pop();
            }
            _ => {}
        }
    }
}

/// Starts the classic wallet interactive terminal UI.
pub fn run(wallet: &ClassicWallet) -> Result<(), ClassicWalletError> {
    let mut terminal = init_terminal()?;
    let result = run_app(&mut terminal, wallet);
    restore_terminal()?;
    result
}

fn init_terminal() -> Result<DefaultTerminal, ClassicWalletError> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(ratatui::init())
}

fn restore_terminal() -> Result<(), ClassicWalletError> {
    ratatui::restore();
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn run_app(
    terminal: &mut DefaultTerminal,
    wallet: &ClassicWallet,
) -> Result<(), ClassicWalletError> {
    let mut app = App::new(wallet);

    loop {
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match (&app.view, key.code) {
                        (View::CreateWallet, KeyCode::Esc)
                        | (View::ImportWalletName, KeyCode::Esc)
                        | (View::ImportWalletPrivateKey, KeyCode::Esc) => app.back_to_wallets(),
                        (View::AddFundingName, KeyCode::Esc)
                        | (View::AddFundingOutpoint, KeyCode::Esc)
                        | (View::AddFundingAmount, KeyCode::Esc) => app.cancel_add_funding(),
                        (View::TransferDestination, KeyCode::Esc)
                        | (View::TransferAmount, KeyCode::Esc)
                        | (View::TransferFee, KeyCode::Esc) => app.cancel_transfer(),
                        (View::JoinFundsFee, KeyCode::Esc) => app.cancel_join_funds(),
                        (View::ConfirmTransferDetails, KeyCode::Char('y')) => {
                            app.send_transfer(wallet)
                        }
                        (View::ConfirmTransferDetails, KeyCode::Char('n') | KeyCode::Esc) => {
                            app.cancel_transfer()
                        }
                        (View::ConfirmJoinFunds, KeyCode::Char('y')) => app.send_join_funds(wallet),
                        (View::ConfirmJoinFunds, KeyCode::Char('n') | KeyCode::Esc) => {
                            app.cancel_join_funds()
                        }
                        (View::RegtestFundName, KeyCode::Esc)
                        | (View::RegtestFundAmount, KeyCode::Esc) => app.cancel_regtest_fund(),
                        (View::ConfirmDeleteWallet, KeyCode::Char('y')) => {
                            app.delete_selected_wallet(wallet);
                        }
                        (View::ConfirmDeleteWallet, KeyCode::Char('n') | KeyCode::Esc) => {
                            app.cancel_delete_wallet();
                        }
                        (View::ConfirmDeleteFund, KeyCode::Char('y')) => {
                            app.delete_selected_fund(wallet);
                        }
                        (View::ConfirmDeleteFund, KeyCode::Char('n') | KeyCode::Esc) => {
                            app.cancel_delete_fund();
                        }
                        (
                            View::ShowPrivateKey,
                            KeyCode::Esc | KeyCode::Backspace | KeyCode::Enter,
                        ) => {
                            app.back_to_wallets();
                        }
                        (View::ShowLink, KeyCode::Esc | KeyCode::Backspace | KeyCode::Enter) => {
                            app.close_link();
                        }
                        (View::CreateWallet, KeyCode::Enter) => app.create_wallet(wallet),
                        (View::ImportWalletName, KeyCode::Enter) => app.accept_import_wallet_name(),
                        (View::ImportWalletPrivateKey, KeyCode::Enter) => app.import_wallet(wallet),
                        (View::AddFundingName, KeyCode::Enter) => app.accept_add_funding_name(),
                        (View::AddFundingOutpoint, KeyCode::Enter) => {
                            app.accept_add_funding_outpoint()
                        }
                        (View::AddFundingAmount, KeyCode::Enter) => {
                            app.add_funding_with_manual_amount(wallet);
                        }
                        (View::AddFundingAmount, KeyCode::Char('r')) => {
                            app.add_funding_from_rpc(wallet)
                        }
                        (View::TransferDestination, KeyCode::Enter) => {
                            app.accept_transfer_destination()
                        }
                        (View::TransferAmount, KeyCode::Enter) => app.accept_transfer_amount(),
                        (View::TransferFee, KeyCode::Enter) => app.accept_transfer_fee(),
                        (View::JoinFundsFee, KeyCode::Enter) => app.accept_join_funds_fee(),
                        (View::RegtestFundName, KeyCode::Enter) => app.accept_regtest_fund_name(),
                        (View::RegtestFundAmount, KeyCode::Enter) => app.regtest_fund(wallet),
                        (View::CreateWallet, code)
                        | (View::ImportWalletName, code)
                        | (View::ImportWalletPrivateKey, code)
                        | (View::AddFundingName, code)
                        | (View::AddFundingOutpoint, code)
                        | (View::AddFundingAmount, code)
                        | (View::TransferDestination, code)
                        | (View::TransferAmount, code)
                        | (View::TransferFee, code)
                        | (View::JoinFundsFee, code)
                        | (View::RegtestFundName, code)
                        | (View::RegtestFundAmount, code) => app.handle_text_input(code),
                        (_, KeyCode::Char('q')) => break,
                        (View::WalletList, KeyCode::Esc) => break,
                        (View::WalletDetails, KeyCode::Esc | KeyCode::Backspace) => {
                            app.back_to_wallets();
                        }
                        (View::WalletDetails, KeyCode::Char('a')) => app.start_add_funding(),
                        (View::WalletDetails, KeyCode::Char('d')) => app.start_delete_fund(),
                        (View::WalletDetails, KeyCode::Char('J')) => app.start_join_funds(),
                        (View::WalletDetails, KeyCode::Char('s')) => app.start_transfer(),
                        (View::WalletDetails, KeyCode::Char('c')) => {
                            app.confirm_selected_transfer(wallet)
                        }
                        (View::WalletDetails, KeyCode::Char('m')) => {
                            app.check_and_confirm_selected_transfer(wallet)
                        }
                        (View::WalletDetails, KeyCode::Char('f')) => app.start_regtest_fund(),
                        (View::WalletDetails, KeyCode::Char('l')) => app.show_selected_fund_link(),
                        (View::WalletDetails, KeyCode::Up | KeyCode::Char('k')) => {
                            app.select_previous_fund()
                        }
                        (View::WalletDetails, KeyCode::Down | KeyCode::Char('j')) => {
                            app.select_next_fund()
                        }
                        (View::WalletList, KeyCode::Char('c')) => app.start_create_wallet(),
                        (View::WalletList, KeyCode::Char('i')) => app.start_import_wallet(),
                        (View::WalletList, KeyCode::Char('d')) => app.start_delete_wallet(),
                        (View::WalletList, KeyCode::Char('p')) => app.show_private_key(wallet),
                        (View::WalletList, KeyCode::Char('l')) => app.show_selected_wallet_link(),
                        (View::WalletList, KeyCode::Up | KeyCode::Char('k')) => {
                            app.select_previous()
                        }
                        (View::WalletList, KeyCode::Down | KeyCode::Char('j')) => app.select_next(),
                        (View::WalletList, KeyCode::Enter) => app.open_selected_wallet(wallet),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    match app.view {
        View::WalletList => render_wallet_list(frame, app),
        View::WalletDetails => render_wallet_details(frame, app),
        View::CreateWallet | View::ImportWalletName | View::ImportWalletPrivateKey => {
            render_wallet_list(frame, app);
            render_input_popup(frame, app);
        }
        View::AddFundingName
        | View::AddFundingOutpoint
        | View::AddFundingAmount
        | View::TransferDestination
        | View::TransferAmount
        | View::TransferFee
        | View::JoinFundsFee
        | View::RegtestFundName
        | View::RegtestFundAmount => {
            render_wallet_details(frame, app);
            render_input_popup(frame, app);
        }
        View::ConfirmDeleteWallet => {
            render_wallet_list(frame, app);
            render_delete_wallet_confirmation_popup(frame, app);
        }
        View::ConfirmDeleteFund => {
            render_wallet_details(frame, app);
            render_delete_fund_confirmation_popup(frame, app);
        }
        View::ConfirmTransferDetails => {
            render_wallet_details(frame, app);
            render_transfer_confirmation_popup(frame, app);
        }
        View::ConfirmJoinFunds => {
            render_wallet_details(frame, app);
            render_join_funds_confirmation_popup(frame, app);
        }
        View::ShowPrivateKey => {
            render_wallet_list(frame, app);
            render_private_key_popup(frame, app);
        }
        View::ShowLink => {
            if app.funds.is_empty() {
                render_wallet_list(frame, app);
            } else {
                render_wallet_details(frame, app);
            }
            render_link_popup(frame, app);
        }
    }
}

fn render_wallet_list(frame: &mut Frame<'_>, app: &App) {
    let chunks = base_layout(frame);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Classic Wallet UI",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(
            "↑/↓: select  Enter: details  c: create  i: import  d: delete  p: private key  l: link  q/Esc: quit",
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let wallet_items: Vec<ListItem> = if app.wallets.is_empty() {
        vec![ListItem::new("No wallets found")]
    } else {
        app.wallets
            .iter()
            .map(|wallet| {
                ListItem::new(format!(
                    "{}  {}",
                    fixed_width(&wallet.name, NAME_COLUMN_WIDTH),
                    wallet.pubkey
                ))
            })
            .collect()
    };

    let wallets = List::new(wallet_items)
        .block(Block::default().title("Wallets").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if !app.wallets.is_empty() {
        state.select(Some(app.selected_wallet));
    }
    frame.render_stateful_widget(wallets, chunks[1], &mut state);

    render_status(frame, app, chunks[2]);
}

fn render_wallet_details(frame: &mut Frame<'_>, app: &App) {
    let chunks = base_layout(frame);

    let selected_wallet = app.selected_wallet();
    let title_text = selected_wallet
        .map(|wallet| format!("Wallet: {}", wallet.name))
        .unwrap_or_else(|| "Wallet details".to_string());

    let help = if app.is_regtest {
        "↑/↓: select fund  s: transfer  J: join  c: confirm  m: check mined+confirm  a: add  d: delete  f: regtest  l: link  Esc: back"
    } else {
        "↑/↓: select fund  s: transfer  J: join  c: confirm  m: check mined+confirm  a: add  d: delete  l: link  Esc: back"
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            title_text,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(help),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let detail_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(3)])
        .split(chunks[1]);

    let total = app.funds.iter().map(|fund| fund.amount).sum::<u64>();
    let pubkey = selected_wallet
        .map(|wallet| wallet.pubkey.as_str())
        .unwrap_or("-");
    let address = selected_wallet
        .map(|wallet| wallet.address.as_str())
        .unwrap_or("-");
    let total_btc = Amount::from_sat(total).to_btc();
    let summary = Paragraph::new(vec![
        Line::from(format!("Public key: {pubkey}")),
        Line::from(format!("Bech32 address: {address}")),
        Line::from(format!(
            "Funds available: {total} sats ({total_btc:.8} BTC)"
        )),
    ])
    .block(Block::default().title("Summary").borders(Borders::ALL));
    frame.render_widget(summary, detail_chunks[0]);

    let fund_items: Vec<ListItem> = if app.funds.is_empty() {
        vec![ListItem::new("No funds available")]
    } else {
        app.funds
            .iter()
            .map(|fund| {
                let mut lines = vec![Line::from(format!(
                    "{}  {} sats  {}",
                    fixed_width(&fund.funding_id, NAME_COLUMN_WIDTH),
                    sats_width(fund.amount),
                    fund.outpoint
                ))];
                if let Some(pending) = &fund.pending {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "  PENDING",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!(
                            " txid: {}  change: {} sats @ vout {}",
                            pending.txid, pending.change_amount, pending.change_vout
                        )),
                    ]));
                }
                ListItem::new(lines)
            })
            .collect()
    };

    let funds = List::new(fund_items)
        .block(
            Block::default()
                .title("Funding entries")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if !app.funds.is_empty() {
        state.select(Some(app.selected_fund));
    }
    frame.render_stateful_widget(funds, detail_chunks[1], &mut state);

    render_status(frame, app, chunks[2]);
}

fn render_input_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(70, 9, frame.area());
    frame.render_widget(Clear, area);

    let (title, label, value) = match app.view {
        View::CreateWallet => ("Create wallet", "Wallet name", app.input.clone()),
        View::ImportWalletName => ("Import wallet", "Wallet name", app.input.clone()),
        View::ImportWalletPrivateKey => (
            "Import wallet",
            "Private key / secret key",
            "*".repeat(app.input.chars().count()),
        ),
        View::AddFundingName => ("Add funds", "Funding name", app.input.clone()),
        View::AddFundingOutpoint => ("Add funds", "Outpoint (txid:vout)", app.input.clone()),
        View::AddFundingAmount => (
            "Add funds",
            "Amount in sats (or press r to fetch from RPC)",
            app.input.clone(),
        ),
        View::TransferDestination => ("Transfer", "Destination public key", app.input.clone()),
        View::TransferAmount => ("Transfer", "Amount in sats", app.input.clone()),
        View::TransferFee => ("Transfer", "Fee in sats (minimum 500)", app.input.clone()),
        View::JoinFundsFee => (
            "Join funds",
            "Fee per input in sats (minimum 500)",
            app.input.clone(),
        ),
        View::RegtestFundName => ("Regtest fund", "Funding name", app.input.clone()),
        View::RegtestFundAmount => ("Regtest fund", "Amount wanted in sats", app.input.clone()),
        _ => unreachable!(),
    };

    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new(label), chunks[0]);

    let input = Paragraph::new(value)
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(input, chunks[1]);

    frame.render_widget(
        Paragraph::new(if matches!(app.view, View::AddFundingAmount) {
            "Enter: submit amount  r: fetch amount from RPC  Esc: cancel"
        } else if matches!(app.view, View::TransferFee) {
            "Enter: review transfer  Esc: cancel"
        } else if matches!(app.view, View::JoinFundsFee) {
            "Enter: review join-funds  Esc: cancel"
        } else {
            "Enter: submit  Esc: cancel"
        })
        .style(Style::default().fg(Color::Yellow)),
        chunks[2],
    );

    let max_cursor_offset = chunks[1].width.saturating_sub(3) as usize;
    let cursor_offset = app.input.chars().count().min(max_cursor_offset) as u16;
    frame.set_cursor_position((chunks[1].x + 1 + cursor_offset, chunks[1].y + 1));
}

fn render_transfer_confirmation_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(80, 11, frame.area());
    frame.render_widget(Clear, area);

    let wallet_name = app
        .selected_wallet()
        .map(|wallet| wallet.name.as_str())
        .unwrap_or("-");
    let fund = app.selected_fund();
    let funding_id = fund.map(|fund| fund.funding_id.as_str()).unwrap_or("-");
    let outpoint = fund
        .map(|fund| fund.outpoint.to_string())
        .unwrap_or_else(|| "-".to_string());
    let available = fund.map(|fund| fund.amount).unwrap_or(0);
    let total_spend = app.transfer_amount.saturating_add(app.transfer_fee);
    let change = available.saturating_sub(total_spend);
    let is_overspend = total_spend > available;

    let block = Block::default()
        .title("Confirm transfer")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(format!("Wallet: {wallet_name}")),
        Line::from(format!(
            "Funding: {funding_id}  {available} sats  {outpoint}"
        )),
        Line::from(format!("Destination pubkey: {}", app.transfer_destination)),
        Line::from(format!("Amount: {} sats", app.transfer_amount)),
        Line::from(format!("Fee: {} sats", app.transfer_fee)),
        Line::from(format!("Expected change: {change} sats")),
        if is_overspend {
            Line::from(vec![Span::styled(
                "Amount plus fee exceeds available funds; confirmation is disabled.",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )])
        } else {
            Line::from("")
        },
        Line::from(vec![
            Span::styled(
                "y",
                Style::default()
                    .fg(if is_overspend {
                        Color::DarkGray
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(if is_overspend {
                ": disabled  "
            } else {
                ": send and leave pending  "
            }),
            Span::styled(
                "n/Esc",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(": cancel"),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_join_funds_confirmation_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(75, 10, frame.area());
    frame.render_widget(Clear, area);

    let wallet_name = app
        .selected_wallet()
        .map(|wallet| wallet.name.as_str())
        .unwrap_or("-");
    let input_count = app.funds.len() as u64;
    let total = app.funds.iter().map(|fund| fund.amount).sum::<u64>();
    let total_fee = app.join_fee_per_input.saturating_mul(input_count);
    let output_amount = total.saturating_sub(total_fee);
    let is_invalid = input_count == 0 || app.join_fee_per_input < 500 || total_fee >= total;

    let block = Block::default()
        .title("Confirm join-funds")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(format!("Wallet: {wallet_name}")),
        Line::from(format!("Inputs: {input_count}")),
        Line::from(format!("Total funds: {total} sats")),
        Line::from(format!("Fee per input: {} sats", app.join_fee_per_input)),
        Line::from(format!("Total fee: {total_fee} sats")),
        Line::from(format!("Joined output amount: {output_amount} sats")),
        if is_invalid {
            Line::from(vec![Span::styled(
                "Invalid join-funds parameters; confirmation is disabled.",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )])
        } else {
            Line::from("")
        },
        Line::from(vec![
            Span::styled(
                "y",
                Style::default()
                    .fg(if is_invalid {
                        Color::DarkGray
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(if is_invalid {
                ": disabled  "
            } else {
                ": send and leave pending  "
            }),
            Span::styled(
                "n/Esc",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(": cancel"),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_delete_wallet_confirmation_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(60, 7, frame.area());
    frame.render_widget(Clear, area);

    let wallet_name = app
        .selected_wallet()
        .map(|wallet| wallet.name.as_str())
        .unwrap_or("-");
    let block = Block::default()
        .title("Confirm deletion")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!("Delete wallet '{wallet_name}'?"))
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new("This also removes locally registered funds and pending transfers."),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new("y: delete  n/Esc: cancel").style(Style::default().fg(Color::Yellow)),
        chunks[2],
    );
}

fn render_delete_fund_confirmation_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(70, 8, frame.area());
    frame.render_widget(Clear, area);

    let fund = app.selected_fund();
    let funding_id = fund.map(|fund| fund.funding_id.as_str()).unwrap_or("-");
    let amount = fund.map(|fund| fund.amount).unwrap_or(0);
    let outpoint = fund
        .map(|fund| fund.outpoint.to_string())
        .unwrap_or_else(|| "-".to_string());
    let block = Block::default()
        .title("Confirm fund deletion")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!("Delete funding entry '{funding_id}'?"))
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(format!("Amount: {amount} sats")), chunks[1]);
    frame.render_widget(Paragraph::new(format!("Outpoint: {outpoint}")), chunks[2]);
    frame.render_widget(
        Paragraph::new("y: delete  n/Esc: cancel").style(Style::default().fg(Color::Yellow)),
        chunks[3],
    );
}

fn render_private_key_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(80, 9, frame.area());
    frame.render_widget(Clear, area);

    let wallet_name = app
        .selected_wallet()
        .map(|wallet| wallet.name.as_str())
        .unwrap_or("-");
    let block = Block::default().title("Private key").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new("WARNING: Never share this private key with anyone.")
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(format!("Wallet: {wallet_name}")), chunks[1]);
    frame.render_widget(
        Paragraph::new(format!(" {}", app.private_key))
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new("Esc/Enter: close").style(Style::default().fg(Color::Yellow)),
        chunks[3],
    );
}

fn render_link_popup(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect_fixed_height(90, 7, frame.area());
    frame.render_widget(Clear, area);

    let block = Block::default().title("Mempool link").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new("Testnet mempool.space link:"), chunks[0]);
    frame.render_widget(
        Paragraph::new(format!(" {}", app.link))
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL)),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new("Esc/Enter: close").style(Style::default().fg(Color::Yellow)),
        chunks[2],
    );
}

fn fixed_width(value: &str, width: usize) -> String {
    let mut text = value.chars().take(width).collect::<String>();
    let len = text.chars().count();
    if len < width {
        text.push_str(&" ".repeat(width - len));
    }
    text
}

fn sats_width(amount: u64) -> String {
    format!("{amount:>width$}", width = SATS_COLUMN_WIDTH)
}

fn centered_rect_fixed_height(percent_x: u16, height: u16, area: Rect) -> Rect {
    let popup_height = height.min(area.height);
    let top = area.height.saturating_sub(popup_height) / 2;
    let bottom = area.height.saturating_sub(popup_height + top);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top),
            Constraint::Length(popup_height),
            Constraint::Length(bottom),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn base_layout(frame: &Frame<'_>) -> Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area())
}

fn render_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().title("Status").borders(Borders::ALL));
    frame.render_widget(status, area);
}
