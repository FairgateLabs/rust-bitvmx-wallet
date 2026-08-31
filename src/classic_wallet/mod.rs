#[allow(clippy::module_inception)]
pub mod classic_wallet;
pub mod config;
pub mod errors;
#[cfg(feature = "ui")]
pub mod tui;

// Re-export everything
pub use config::*;
pub use errors::*;
