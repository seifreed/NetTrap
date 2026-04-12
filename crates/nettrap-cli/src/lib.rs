pub mod cli;
pub mod config;
pub mod custom_response;
pub mod database;
pub mod distributed;
pub mod engine;
pub mod execute;
pub mod faketime;
pub mod handler_registry;
pub mod hexdump;
pub mod i18n;
pub mod listener_config;
pub mod listener_context;
pub mod listener_runtime;
pub mod listeners;
pub mod mkcert;
pub mod nbi;
pub mod output;
pub mod process_filter;
pub mod protocol_handlers;
pub mod router_setup;
pub mod session;
pub mod startup;
pub mod template;
pub mod tls_manager;
pub mod types;
pub mod utils;
pub mod vfs;
pub mod webroot;
pub mod windows_setup;

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

pub fn setup_logging(
    verbose: bool,
    quiet: bool,
    log_file: Option<&std::path::Path>,
    no_console: bool,
    log_syslog: bool,
) -> Result<()> {
    let filter = if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if log_syslog {
        #[cfg(target_os = "linux")]
        let syslog_path = std::path::Path::new("/var/log/nettrap.log");
        #[cfg(not(target_os = "linux"))]
        let syslog_path = std::path::Path::new("nettrap.log");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(syslog_path)?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_target(false)
            .with_ansi(false)
            .init();
    } else if let Some(path) = log_file {
        let file = std::fs::File::create(path)?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_target(false)
            .with_ansi(false)
            .init();
    } else if no_console {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::sink)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .init();
    }

    Ok(())
}
