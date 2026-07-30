pub mod fingerprint;
pub mod output;
pub mod ports;
pub mod scanner;
pub mod target;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PscanError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PscanError>;
