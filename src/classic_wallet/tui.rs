use super::{classic_wallet::ClassicWallet, errors::ClassicWalletError};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    DefaultTerminal, Frame,
};
use std::{io, time::Duration};

struct App {
    status: String,
    wallet_items: Vec<String>,
}

impl App {
    fn new(wallet: &ClassicWallet) -> Self {
        let mut app = Self {
            status: "Press r to refresh, q/Esc to quit".to_string(),
            wallet_items: Vec::new(),
        };
        app.refresh_wallets(wallet);
        app
    }

    fn refresh_wallets(&mut self, wallet: &ClassicWallet) {
        match wallet.get_wallets() {
            Ok(wallets) if wallets.is_empty() => {
                self.wallet_items = vec!["No wallets found".to_string()];
                self.status = "Wallet list refreshed".to_string();
            }
            Ok(wallets) => {
                self.wallet_items = wallets
                    .into_iter()
                    .map(|(name, pubkey)| format!("{name}  {pubkey}"))
                    .collect();
                self.status = "Wallet list refreshed".to_string();
            }
            Err(e) => {
                self.wallet_items.clear();
                self.status = format!("Failed to load wallets: {e}");
            }
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

fn run_app(terminal: &mut DefaultTerminal, wallet: &ClassicWallet) -> Result<(), ClassicWalletError> {
    let mut app = App::new(wallet);

    loop {
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') => app.refresh_wallets(wallet),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Classic Wallet UI",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw("q/Esc: quit  r: refresh"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let wallet_items: Vec<ListItem> = app
        .wallet_items
        .iter()
        .map(|item| ListItem::new(item.as_str()))
        .collect();
    let wallets = List::new(wallet_items).block(
        Block::default()
            .title("Wallets")
            .borders(Borders::ALL),
    );
    frame.render_widget(wallets, chunks[1]);

    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().title("Status").borders(Borders::ALL));
    frame.render_widget(status, chunks[2]);
}
