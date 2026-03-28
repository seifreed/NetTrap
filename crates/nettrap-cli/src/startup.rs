use clap::Parser;

pub fn run() -> crate::Result<()> {
    let cli = crate::cli::Cli::parse();
    
    let config_path = cli.config.clone();
    
    crate::setup_logging(cli.verbose, cli.quiet)?;
    
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        crate::handle_command(cli.command, cli.verbose, config_path).await
    })
}