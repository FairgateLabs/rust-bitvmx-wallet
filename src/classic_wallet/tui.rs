use super::{classic_wallet::ClassicWallet, errors::ClassicWalletError};
use bitcoin::OutPoint;
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
use std::{io, rc::Rc, time::Duration};

struct WalletItem {
    name: String,
    pubkey: String,
}

enum View {
    WalletList,
    WalletDetails,
    CreateWallet,
    ImportWalletName,
    ImportWalletPrivateKey,
    ConfirmDeleteWallet,
}

struct App {
    status: String,
    wallets: Vec<WalletItem>,
    selected_wallet: usize,
    view: View,
    funds: Vec<(String, OutPoint, u64)>,
    input: String,
    import_wallet_name: String,
}

impl App {
    fn new(wallet: &ClassicWallet) -> Self {
        let mut app = Self {
            status: "Press ↑/↓ to select, Enter for details, c to create, i to import, d to delete, q/Esc to quit"
                .to_string(),
            wallets: Vec::new(),
            selected_wallet: 0,
            view: View::WalletList,
            funds: Vec::new(),
            input: String::new(),
            import_wallet_name: String::new(),
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

    fn open_selected_wallet(&mut self, wallet: &ClassicWallet) {
        let Some(selected_wallet) = self.selected_wallet() else {
            self.status = "No wallet selected".to_string();
            return;
        };

        match wallet.list_funds(&selected_wallet.name) {
            Ok(funds) => {
                let wallet_name = selected_wallet.name.clone();
                let total = funds.iter().map(|(_, _, amount)| amount).sum::<u64>();
                self.funds = funds;
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
                        (View::ConfirmDeleteWallet, KeyCode::Char('y')) => {
                            app.delete_selected_wallet(wallet);
                        }
                        (View::ConfirmDeleteWallet, KeyCode::Char('n') | KeyCode::Esc) => {
                            app.cancel_delete_wallet();
                        }
                        (View::CreateWallet, KeyCode::Enter) => app.create_wallet(wallet),
                        (View::ImportWalletName, KeyCode::Enter) => app.accept_import_wallet_name(),
                        (View::ImportWalletPrivateKey, KeyCode::Enter) => app.import_wallet(wallet),
                        (View::CreateWallet, code)
                        | (View::ImportWalletName, code)
                        | (View::ImportWalletPrivateKey, code) => app.handle_text_input(code),
                        (_, KeyCode::Char('q')) => break,
                        (View::WalletList, KeyCode::Esc) => break,
                        (View::WalletDetails, KeyCode::Esc | KeyCode::Backspace) => {
                            app.back_to_wallets();
                        }
                        (_, KeyCode::Char('r')) => {
                            app.refresh_wallets(wallet);
                            if matches!(app.view, View::WalletDetails) {
                                app.open_selected_wallet(wallet);
                            }
                        }
                        (View::WalletList, KeyCode::Char('c')) => app.start_create_wallet(),
                        (View::WalletList, KeyCode::Char('i')) => app.start_import_wallet(),
                        (View::WalletList, KeyCode::Char('d')) => app.start_delete_wallet(),
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
        View::ConfirmDeleteWallet => {
            render_wallet_list(frame, app);
            render_delete_confirmation_popup(frame, app);
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
            "↑/↓: select  Enter: details  c: create  i: import  d: delete  r: refresh  q/Esc: quit",
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let wallet_items: Vec<ListItem> = if app.wallets.is_empty() {
        vec![ListItem::new("No wallets found")]
    } else {
        app.wallets
            .iter()
            .map(|wallet| ListItem::new(format!("{}  {}", wallet.name, wallet.pubkey)))
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

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            title_text,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw("Esc/Backspace: back  r: refresh  q: quit"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let detail_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(3)])
        .split(chunks[1]);

    let total = app.funds.iter().map(|(_, _, amount)| amount).sum::<u64>();
    let pubkey = selected_wallet
        .map(|wallet| wallet.pubkey.as_str())
        .unwrap_or("-");
    let summary = Paragraph::new(vec![
        Line::from(format!("Public key: {pubkey}")),
        Line::from(format!("Funds available: {total} sats")),
    ])
    .block(Block::default().title("Summary").borders(Borders::ALL));
    frame.render_widget(summary, detail_chunks[0]);

    let fund_items: Vec<ListItem> = if app.funds.is_empty() {
        vec![ListItem::new("No funds available")]
    } else {
        app.funds
            .iter()
            .map(|(funding_id, outpoint, amount)| {
                ListItem::new(format!("{funding_id}  {amount} sats  {outpoint}"))
            })
            .collect()
    };

    let funds = List::new(fund_items).block(
        Block::default()
            .title("Funding entries")
            .borders(Borders::ALL),
    );
    frame.render_widget(funds, detail_chunks[1]);

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
        Paragraph::new("Enter: submit  Esc: cancel").style(Style::default().fg(Color::Yellow)),
        chunks[2],
    );

    let max_cursor_offset = chunks[1].width.saturating_sub(3) as usize;
    let cursor_offset = app.input.chars().count().min(max_cursor_offset) as u16;
    frame.set_cursor_position((chunks[1].x + 1 + cursor_offset, chunks[1].y + 1));
}

fn render_delete_confirmation_popup(frame: &mut Frame<'_>, app: &App) {
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
