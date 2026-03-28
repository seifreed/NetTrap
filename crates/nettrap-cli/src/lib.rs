pub mod cli;
pub mod config;
pub mod engine;
pub mod startup;

pub use cli::*;
pub use config::*;
pub use engine::*;
pub use startup::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Core(nettrap_core::Error),
    Io(std::io::Error),
    Config(String),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Core(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Config(s) => write!(f, "Config error: {}", s),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<nettrap_core::Error> for Error {
    fn from(e: nettrap_core::Error) -> Self {
        Error::Core(e)
    }
}

pub fn setup_logging(verbose: bool, quiet: bool) -> Result<()> {
    let filter = if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(filter)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
    
    Ok(())
}