use thiserror::Error;

#[derive(Error, Debug)]
pub enum MihomoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MihomoError>;
