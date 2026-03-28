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
    let cli = Cli::parse();
    
    let config_path = cli.config.clone();
    
    nettrap_cli::setup_logging(cli.verbose, cli.quiet)?;
    
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| nettrap_cli::Error::Other(format!("Failed to create runtime: {}", e)))?;
    
    rt.block_on(async {
        nettrap_cli::handle_command(cli.command, cli.verbose, config_path).await
    })
}