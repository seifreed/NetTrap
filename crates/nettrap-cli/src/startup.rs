use clap::Parser;

pub fn run() -> crate::Result<()> {
    let cli = crate::cli::Cli::parse();
    let config_path = cli.config.clone();
    let stop_flag = cli.stop_flag.clone();
    crate::setup_logging(cli.verbose, cli.quiet, cli.log_file.as_deref(), cli.no_console, cli.log_syslog)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        crate::handle_command(cli.command, cli.verbose, config_path, stop_flag).await
    })
}