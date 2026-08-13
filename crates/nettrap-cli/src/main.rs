use clap::Parser;
use nettrap_cli::cli::Cli;

type Result<T> = std::result::Result<T, nettrap_cli::Error>;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    configure_windows_arm64_runtime();

    let cli = Cli::parse();

    let config_path = cli.config.clone();
    let stop_flag = cli.stop_flag.clone();

    let log_level = match &cli.command {
        nettrap_cli::cli::Commands::Run(args) => args.log_level.clone(),
        _ => None,
    };

    nettrap_cli::setup_logging(
        cli.verbose,
        cli.quiet,
        cli.log_file.as_deref(),
        cli.no_console,
        cli.log_syslog,
        log_level.as_deref(),
    )?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| nettrap_cli::Error::Other(format!("Failed to create runtime: {}", e)))?;

    rt.block_on(async {
        nettrap_cli::handle_command(cli.command, cli.verbose, config_path, stop_flag).await
    })
}

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
fn configure_windows_arm64_runtime() {
    use std::path::PathBuf;

    fn prepend_path(dir: PathBuf) {
        if !dir.exists() {
            return;
        }

        let current = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![dir];
        paths.extend(std::env::split_paths(&current));

        if let Ok(joined) = std::env::join_paths(paths) {
            unsafe {
                std::env::set_var("PATH", joined);
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            prepend_path(dir.to_path_buf());
        }
    }

    prepend_path(PathBuf::from(r"C:\Windows\System32\Npcap"));
    prepend_path(PathBuf::from(r"C:\Program Files\Npcap"));
}

#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
fn configure_windows_arm64_runtime() {}
