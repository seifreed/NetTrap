use nettrap_fsutil::{append_regular_file, create_regular_file};

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
pub(crate) mod host_filter;
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
pub mod session;
pub mod startup;
pub mod template;
pub mod utils;
pub mod vfs;
pub mod webroot;
pub mod windows_setup;

#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::{Mutex, MutexGuard};

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn lock_current_dir() -> MutexGuard<'static, ()> {
        CWD_LOCK.lock().expect("cwd test lock poisoned")
    }
}

pub use cli::*;
pub use config::*;
pub use engine::*;
pub use startup::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] nettrap_core::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("{0}")]
    Other(String),
}

impl From<nettrap_distributed::Error> for Error {
    fn from(e: nettrap_distributed::Error) -> Self {
        match e {
            nettrap_distributed::Error::Io(e) => Error::Io(e),
            nettrap_distributed::Error::Config(s) => Error::Config(s),
            nettrap_distributed::Error::Other(s) => Error::Other(s),
        }
    }
}

/// Resolve the tracing filter directive from the explicit `--log-level` flag
/// (if any) and the `--verbose`/`--quiet` booleans.
///
/// `--log-level` takes precedence when set and is validated against the known
/// levels; an unknown value is a hard error rather than being silently ignored.
/// When no explicit
/// level is given, fall back to `--quiet` (error) / `--verbose` (debug) / info.
fn resolve_log_filter(verbose: bool, quiet: bool, log_level: Option<&str>) -> Result<&'static str> {
    if let Some(level) = log_level {
        let trimmed = level.trim_matches([' ', '\t']);
        if trimmed.is_empty()
            || trimmed
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return Err(Error::Config(format!(
                "invalid --log-level '{}'; expected one of: error, warn, info, debug, trace",
                level
            )));
        }

        return match trimmed.to_ascii_lowercase().as_str() {
            "error" => Ok("error"),
            "warn" | "warning" => Ok("warn"),
            "info" => Ok("info"),
            "debug" => Ok("debug"),
            "trace" => Ok("trace"),
            other => Err(Error::Config(format!(
                "invalid --log-level '{}'; expected one of: error, warn, info, debug, trace",
                other
            ))),
        };
    }

    Ok(if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    })
}

pub fn setup_logging(
    verbose: bool,
    quiet: bool,
    log_file: Option<&std::path::Path>,
    no_console: bool,
    log_syslog: bool,
    log_level: Option<&str>,
) -> Result<()> {
    let filter = resolve_log_filter(verbose, quiet, log_level)?;

    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if log_syslog {
        #[cfg(target_os = "linux")]
        let syslog_path = std::path::Path::new("/var/log/nettrap.log");
        #[cfg(not(target_os = "linux"))]
        let syslog_path = std::path::Path::new("nettrap.log");

        let file = create_syslog_file(syslog_path)?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_target(false)
            .with_ansi(false)
            .init();
    } else if let Some(path) = log_file {
        let file = create_log_file(path)?;
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

fn create_log_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    create_regular_file(path)
}

fn create_syslog_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    append_regular_file(path)
}

#[cfg(test)]
mod logging_tests {
    use super::create_log_file;
    #[cfg(unix)]
    use super::create_syslog_file;

    #[test]
    fn create_log_file_creates_parent_directories() {
        let root =
            std::env::temp_dir().join(format!("nettrap-log-parent-{}", uuid::Uuid::new_v4()));
        let path = root.join("nested").join("nettrap.log");

        let _file = create_log_file(&path).expect("log file parent should be created");

        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn create_log_file_rejects_symlinked_parent_directory() {
        let root =
            std::env::temp_dir().join(format!("nettrap-log-symlink-{}", uuid::Uuid::new_v4()));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let path = linked_parent.join("nettrap.log");
        let err = create_log_file(&path).expect_err("symlinked parent should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn create_syslog_file_rejects_symlinked_final_path() {
        let root =
            std::env::temp_dir().join(format!("nettrap-syslog-symlink-{}", uuid::Uuid::new_v4()));
        let real_parent = root.join("real");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        let target = real_parent.join("nettrap.log");
        std::fs::write(&target, "existing").expect("write target");
        let link = root.join("nettrap.log");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = create_syslog_file(&link).expect_err("symlinked final path should be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "existing");
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_log_filter;

    #[test]
    fn explicit_log_level_overrides_verbose_and_quiet() {
        assert_eq!(
            resolve_log_filter(true, true, Some("warn")).unwrap(),
            "warn"
        );
        assert_eq!(
            resolve_log_filter(false, false, Some("DEBUG")).unwrap(),
            "debug"
        );
        assert_eq!(
            resolve_log_filter(false, false, Some("warning")).unwrap(),
            "warn"
        );
        assert_eq!(
            resolve_log_filter(false, false, Some("  trace  ")).unwrap(),
            "trace"
        );
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let err = resolve_log_filter(false, false, Some("bogus")).unwrap_err();
        assert!(err.to_string().contains("invalid --log-level 'bogus'"));
    }

    #[test]
    fn falls_back_to_verbose_quiet_when_no_explicit_level() {
        assert_eq!(resolve_log_filter(false, false, None).unwrap(), "info");
        assert_eq!(resolve_log_filter(true, false, None).unwrap(), "debug");
        assert_eq!(resolve_log_filter(false, true, None).unwrap(), "error");
        assert_eq!(resolve_log_filter(true, true, None).unwrap(), "error");
    }
}
