use crate::cli::{Commands, RunArgs, TlsArgs, TlsCommands};

use super::Engine;
use super::config_load::{apply_cli_overrides, load_api_config, load_config};

pub async fn handle_command(
    command: Commands,
    verbose: bool,
    config_path: Option<std::path::PathBuf>,
    stop_flag: Option<std::path::PathBuf>,
) -> crate::Result<()> {
    match command {
        Commands::Run(args) => {
            let engine = build_engine(&args, verbose, config_path).await?;
            engine.run(stop_flag).await
        }
        Commands::Config(args) => super::handle_config(&args, config_path),
        Commands::Pcap(args) => super::handle_pcap(&args, verbose),
        Commands::Report(args) => super::handle_report(&args),
        Commands::Status(args) => super::handle_status(&args),
        Commands::Api(args) => {
            let config = load_api_config(config_path, Some(args.bind.as_str()))?;
            Engine::api_only(config).run(stop_flag).await
        }
        Commands::Tls(args) => handle_tls_command(&args).await,
    }
}

async fn handle_tls_command(args: &TlsArgs) -> crate::Result<()> {
    match &args.command {
        TlsCommands::Status => {
            crate::mkcert::print_status().map_err(crate::Error::Other)?;
            Ok(())
        }
        TlsCommands::InstallMkcert => crate::mkcert::install_mkcert()
            .await
            .map_err(crate::Error::Other),
        TlsCommands::Install => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            crate::mkcert::install_ca().map_err(crate::Error::Other)
        }
        TlsCommands::Generate(gen_args) => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            let hosts: Vec<&str> = gen_args.hostnames.iter().map(String::as_str).collect();
            let (cert, key) = crate::mkcert::generate_cert(&hosts, &gen_args.output_dir)
                .map_err(crate::Error::Other)?;
            println!("Certificate: {}", cert.display());
            println!("Private key: {}", key.display());
            Ok(())
        }
        TlsCommands::Caroot => {
            if let Some(caroot) =
                crate::mkcert::mkcert_caroot_result().map_err(crate::Error::Other)?
            {
                println!("{}", caroot.display());
            } else {
                println!("mkcert CAROOT not found. Is mkcert installed?");
            }
            Ok(())
        }
    }
}

pub(super) async fn build_engine(
    args: &RunArgs,
    _verbose: bool,
    config_path: Option<std::path::PathBuf>,
) -> crate::Result<Engine> {
    let mut config = load_config(config_path)?;
    apply_cli_overrides(&mut config, args)?;
    config.finalize_after_cli_overrides()?;

    Ok(Engine::new(
        config,
        args.intercept,
        args.interface.clone(),
        args.output.clone(),
        args.pcap_path.clone(),
        args.intercept,
        false,
    ))
}
