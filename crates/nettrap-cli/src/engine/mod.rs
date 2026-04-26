use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::cli::Commands;
use crate::config::EngineConfig;
use crate::engine::interceptor::{RunningInterceptor, spawn_interceptor};
use crate::engine::shutdown::{ShutdownContext, execute_shutdown};
use crate::engine::startup::{
    StartupContext, StartupMode, build_listener_context, create_startup_context, init_distributed,
    init_faketime, init_windows_ca_trust, init_windows_network, with_database,
};
use crate::listeners::{run_tcp_listener, run_udp_listener};

mod interceptor;
mod shutdown;
mod startup;

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
        Commands::Config(args) => handle_config(&args, config_path),
        Commands::Pcap(args) => handle_pcap(&args, verbose),
        Commands::Report(args) => handle_report(&args),
        Commands::Status(args) => handle_status(&args),
        Commands::Test(args) => handle_test(&args),
        Commands::Tui(_args) => {
            tracing::info!(
                "TUI mode not yet fully implemented - use 'nettrap report' for HTML reports"
            );
            Ok(())
        }
        Commands::Api(args) => {
            let config = load_api_config(config_path, Some(args.bind.as_str()))?;

            let engine = Engine::api_only(config);
            engine.run(stop_flag).await
        }
        Commands::Tls(args) => handle_tls_command(&args),
    }
}

fn handle_tls_command(args: &crate::cli::TlsArgs) -> crate::Result<()> {
    match &args.command {
        crate::cli::TlsCommands::Status => {
            crate::mkcert::print_status();
            Ok(())
        }
        crate::cli::TlsCommands::InstallMkcert => {
            crate::mkcert::install_mkcert().map_err(crate::Error::Other)
        }
        crate::cli::TlsCommands::Install => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            crate::mkcert::install_ca().map_err(crate::Error::Other)
        }
        crate::cli::TlsCommands::Generate(gen_args) => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            let hosts: Vec<&str> = gen_args.hostnames.iter().map(|s| s.as_str()).collect();
            let (cert, key) = crate::mkcert::generate_cert(&hosts, &gen_args.output_dir)
                .map_err(crate::Error::Other)?;
            println!("Certificate: {}", cert.display());
            println!("Private key: {}", key.display());
            Ok(())
        }
        crate::cli::TlsCommands::Caroot => {
            if let Some(caroot) = crate::mkcert::mkcert_caroot() {
                println!("{}", caroot.display());
            } else {
                println!("mkcert CAROOT not found. Is mkcert installed?");
            }
            Ok(())
        }
    }
}

async fn build_engine(
    args: &crate::cli::RunArgs,
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
        args.intercept,
        false,
    ))
}

async fn start_api_server(
    bind: &str,
    flow_manager: Arc<nettrap_flow::FlowManager>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
    background_tasks: &mut Vec<JoinHandle<()>>,
) -> crate::Result<()> {
    let addr = bind
        .parse::<std::net::SocketAddr>()
        .map_err(|e| crate::Error::Config(format!("Invalid api_bind '{}': {}", bind, e)))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let router = nettrap_api::create_router(nettrap_api::ApiState::with_runtime_health(
        flow_manager,
        Arc::clone(&runtime_health),
    ));

    tracing::info!("REST API listening on {}", local_addr);
    runtime_health.set_api_running();

    background_tasks.push(tokio::spawn(async move {
        if let Err(err) = nettrap_api::serve(listener, router).await {
            runtime_health.set_api_failed(err.to_string());
            let _ = fatal_runtime_tx.send(format!("API server failed: {}", err));
            tracing::warn!("API server exited with error: {}", err);
        }
    }));

    Ok(())
}

fn load_config(config_path: Option<std::path::PathBuf>) -> crate::Result<EngineConfig> {
    if let Some(path) = config_path {
        return EngineConfig::from_file(&path);
    }

    // Platform-specific default config paths
    #[cfg(not(target_os = "windows"))]
    let default_paths: &[&str] = &["/etc/nettrap/config.toml"];

    #[cfg(target_os = "windows")]
    let default_paths: &[&str] = &["C:\\ProgramData\\NetTrap\\config.toml", ".\\config.toml"];

    for path_str in default_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return EngineConfig::from_file(path);
        }
    }

    let mut config = EngineConfig::default();
    config.prepare_runtime_defaults()?;
    Ok(config)
}

fn prepare_loaded_api_config(
    mut config: EngineConfig,
    api_bind_override: Option<&str>,
) -> crate::Result<EngineConfig> {
    if let Some(bind) = api_bind_override {
        config.api_bind = Some(bind.to_string());
    }
    config.prepare_api_defaults()?;
    Ok(config)
}

fn load_api_config(
    config_path: Option<std::path::PathBuf>,
    api_bind_override: Option<&str>,
) -> crate::Result<EngineConfig> {
    if let Some(path) = config_path {
        return prepare_loaded_api_config(
            EngineConfig::from_file_declarative(&path)?,
            api_bind_override,
        );
    }

    #[cfg(not(target_os = "windows"))]
    let default_paths: &[&str] = &["/etc/nettrap/config.toml"];

    #[cfg(target_os = "windows")]
    let default_paths: &[&str] = &["C:\\ProgramData\\NetTrap\\config.toml", ".\\config.toml"];

    for path_str in default_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return prepare_loaded_api_config(
                EngineConfig::from_file_declarative(path)?,
                api_bind_override,
            );
        }
    }

    prepare_loaded_api_config(EngineConfig::default(), api_bind_override)
}

fn apply_cli_overrides(config: &mut EngineConfig, args: &crate::cli::RunArgs) -> crate::Result<()> {
    if !args.ports.is_empty() {
        let mut requested_ports = Vec::new();
        let mut seen_ports = std::collections::HashSet::new();
        for port in &args.ports {
            if seen_ports.insert(*port) {
                requested_ports.push(*port);
            }
        }

        config
            .blacklist_ports_tcp
            .retain(|port| !seen_ports.contains(port));
        config
            .blacklist_ports_udp
            .retain(|port| !seen_ports.contains(port));

        let requested_port_set: std::collections::HashSet<u16> =
            requested_ports.iter().copied().collect();
        let mut selected_listeners: Vec<_> = std::mem::take(&mut config.listeners)
            .into_iter()
            .filter(|listener| requested_port_set.contains(&listener.port))
            .collect();

        for port in requested_ports {
            let covered_by_spawnable_listener = selected_listeners
                .iter()
                .any(|listener| listener.port == port && listener_should_spawn(config, listener));

            if !covered_by_spawnable_listener {
                selected_listeners.push(build_cli_listener_for_port(&selected_listeners, port)?);
            }
        }

        config.listeners = selected_listeners;
    }

    if let Some(ref output) = args.output {
        config.output_path = Some(output.to_string_lossy().to_string());
    }

    if args.pcap {
        config.pcap_enabled = true;
    }

    if let Some(ref pcap_path) = args.pcap_path {
        config.pcap_enabled = true;
        config.pcap_path = Some(pcap_path.to_string_lossy().to_string());
    }

    if args.attribution {
        config.attribution_enabled = true;
    }

    if let Some(ref fmt) = args.report_format {
        config.output_format = fmt.clone();
    }

    Ok(())
}

fn build_cli_listener_for_port(
    existing_listeners: &[crate::config::ListenerConfig],
    port: u16,
) -> crate::Result<crate::config::ListenerConfig> {
    use nettrap_core::prelude::Protocol;

    let matching_listeners: Vec<_> = existing_listeners
        .iter()
        .filter(|listener| listener.port == port)
        .collect();

    let mut matching_protocols: Vec<Protocol> = matching_listeners
        .iter()
        .map(|listener| listener.protocol)
        .collect();
    matching_protocols.sort_unstable_by_key(|protocol| match protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        _ => 2,
    });
    matching_protocols.dedup();

    if matching_protocols.len() > 1 {
        return Err(crate::Error::Config(format!(
            "CLI --ports {} is ambiguous: existing listeners on that port use both TCP and UDP",
            port
        )));
    }

    if let Some(base_listener) = matching_listeners.first() {
        for other in matching_listeners.iter().skip(1) {
            if !cli_listener_bases_are_compatible(base_listener, other) {
                return Err(crate::Error::Config(format!(
                    "CLI --ports {} is ambiguous: existing listeners on that port have incompatible settings",
                    port
                )));
            }
        }

        let mut listener = (*base_listener).clone();
        listener.name = format!("cli_{}", port);
        listener.port = port;
        listener.port_range = None;
        listener.enabled = true;
        listener.hidden = false;
        return Ok(listener);
    }

    Ok(crate::config::ListenerConfig::new(
        format!("cli_{}", port),
        port,
    ))
}

fn cli_listener_bases_are_compatible(
    base: &crate::config::ListenerConfig,
    other: &crate::config::ListenerConfig,
) -> bool {
    fn normalized_listener_signature(
        listener: &crate::config::ListenerConfig,
    ) -> serde_json::Value {
        let mut normalized = listener.clone();
        normalized.name.clear();
        normalized.enabled = true;
        normalized.hidden = false;
        normalized.port_range = None;
        serde_json::to_value(normalized).expect("listener config should serialize")
    }

    normalized_listener_signature(base) == normalized_listener_signature(other)
}

fn handle_config(
    args: &crate::cli::ConfigArgs,
    config_path: Option<std::path::PathBuf>,
) -> crate::Result<()> {
    if args.defaults {
        let config = EngineConfig::default();
        let toml_str = toml::to_string_pretty(&config)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;
        println!("{}", toml_str);
        return Ok(());
    }

    if args.check {
        if let Some(ref path) = config_path {
            return check_config_paths(std::slice::from_ref(path));
        }

        let files = std::fs::read_dir(".")?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .map(|e| e.path())
            .collect::<Vec<_>>();

        return check_config_paths(&files);
    }

    let config = if let Some(ref path) = config_path {
        EngineConfig::from_file_declarative(path)?
    } else {
        EngineConfig::default()
    };

    if let Some(ref output) = args.output {
        config.to_file(&output.to_string_lossy())?;
        println!("Config written to {}", output.display());
    } else {
        let toml_str = toml::to_string_pretty(&config)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;
        println!("{}", toml_str);
    }

    Ok(())
}

fn check_config_paths(paths: &[std::path::PathBuf]) -> crate::Result<()> {
    let mut invalid_configs = Vec::new();

    for path in paths {
        match EngineConfig::from_file(path) {
            Ok(_) => println!("✓ {} is valid", path.display()),
            Err(err) => {
                println!("✗ {} is invalid: {}", path.display(), err);
                invalid_configs.push((path.clone(), err));
            }
        }
    }

    if invalid_configs.is_empty() {
        return Ok(());
    }

    let invalid_summary = invalid_configs
        .iter()
        .map(|(path, _)| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    Err(crate::Error::Config(format!(
        "Configuration validation failed for {} file(s): {}",
        invalid_configs.len(),
        invalid_summary
    )))
}

fn handle_pcap(args: &crate::cli::PcapArgs, _verbose: bool) -> crate::Result<()> {
    Err(crate::Error::Other(format!(
        "Offline PCAP processing is not implemented yet for '{}'; use `nettrap run --pcap` to capture PCAP output",
        args.input.display()
    )))
}

fn handle_report(args: &crate::cli::ReportArgs) -> crate::Result<()> {
    let mut events = load_report_events(&args.input)?;
    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));

    let format = match args.format.as_deref() {
        Some(raw) => raw
            .parse::<crate::output::OutputFormat>()
            .map_err(|err| crate::Error::Config(err.to_string()))?,
        None => args
            .output
            .as_deref()
            .and_then(infer_report_format_from_path)
            .unwrap_or(crate::output::OutputFormat::Json),
    };

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| args.input.with_extension(format.extension()));
    crate::output::export_nbis(&events, format, &output_path)?;

    println!(
        "Report written to {} ({} event(s), {})",
        output_path.display(),
        events.len(),
        format.extension()
    );
    Ok(())
}

fn load_report_events(path: &Path) -> crate::Result<Vec<crate::nbi::NetworkBehaviorIndicator>> {
    let content = std::fs::read_to_string(path)?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let parse_as_json_document = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || trimmed.starts_with('[')
        || (trimmed.starts_with('{') && !trimmed.contains('\n'));

    if parse_as_json_document {
        let mut events = parse_report_json_document(trimmed).map_err(|err| {
            crate::Error::Other(format!(
                "Failed to parse report input '{}': {}",
                path.display(),
                err
            ))
        })?;
        normalize_report_event_ids(&mut events);
        return Ok(events);
    }

    let loaded = crate::output::load_nbis_from_jsonl_detailed(path);
    if let Some(err) = loaded.read_error {
        return Err(crate::Error::Other(format!(
            "Failed to read report input '{}': {}",
            path.display(),
            err
        )));
    }
    if loaded.invalid_lines > 0 {
        return Err(crate::Error::Other(format!(
            "Report input '{}' contains {} invalid JSONL line(s)",
            path.display(),
            loaded.invalid_lines
        )));
    }

    Ok(loaded.events)
}

fn parse_report_json_document(
    content: &str,
) -> Result<Vec<crate::nbi::NetworkBehaviorIndicator>, serde_json::Error> {
    if content.starts_with('[') {
        serde_json::from_str(content)
    } else {
        serde_json::from_str(content).map(|event| vec![event])
    }
}

fn normalize_report_event_ids(events: &mut [crate::nbi::NetworkBehaviorIndicator]) {
    for event in events {
        event.event_id = event.normalized_event_id();
    }
}

fn infer_report_format_from_path(path: &Path) -> Option<crate::output::OutputFormat> {
    let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if file_name.ends_with(".sarif.json") {
        return Some(crate::output::OutputFormat::Sarif);
    }

    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(crate::output::OutputFormat::Json),
        "jsonl" | "ndjson" => Some(crate::output::OutputFormat::Jsonl),
        "sarif" => Some(crate::output::OutputFormat::Sarif),
        "toon" => Some(crate::output::OutputFormat::Toon),
        "csv" => Some(crate::output::OutputFormat::Csv),
        _ => None,
    }
}

fn handle_status(args: &crate::cli::StatusArgs) -> crate::Result<()> {
    if args.json {
        println!("{{\"status\": \"ok\", \"version\": \"0.1.0\"}}");
    } else {
        println!("NetTrap Status: OK");
        println!("Version: 0.1.0");
    }
    Ok(())
}

fn handle_test(_args: &crate::cli::TestArgs) -> crate::Result<()> {
    println!("Running tests...");
    Ok(())
}

pub struct Engine {
    config: EngineConfig,
    intercept_enabled: bool,
    require_interceptor: bool,
    allow_zero_listeners: bool,
    api_only_mode: bool,
    interface: Option<String>,
    output_override: Option<PathBuf>,
}

impl Engine {
    pub fn new(
        config: EngineConfig,
        intercept_enabled: bool,
        interface: Option<String>,
        output_override: Option<PathBuf>,
        require_interceptor: bool,
        allow_zero_listeners: bool,
    ) -> Self {
        Self {
            config,
            intercept_enabled,
            require_interceptor,
            allow_zero_listeners,
            api_only_mode: false,
            interface,
            output_override,
        }
    }

    pub fn api_only(config: EngineConfig) -> Self {
        Self {
            config,
            intercept_enabled: false,
            require_interceptor: false,
            allow_zero_listeners: true,
            api_only_mode: true,
            interface: None,
            output_override: None,
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub async fn run(&self, stop_flag: Option<std::path::PathBuf>) -> crate::Result<()> {
        tracing::info!("Starting NetTrap engine...");
        let api_only_mode = self.api_only_mode;

        log_network_mode(&self.config);
        if !api_only_mode {
            log_redirect_mode(&self.config);
        }

        validate_listener_presence(
            &self.config,
            self.allow_zero_listeners || self.api_only_mode,
        )?;

        if !api_only_mode {
            init_windows_network(&self.config);
            init_windows_ca_trust(&self.config);
        }

        let startup = create_startup_context(
            &self.config,
            self.output_override.clone(),
            if api_only_mode {
                StartupMode::ApiOnly
            } else {
                StartupMode::Standard
            },
        )?;
        let mut startup = if api_only_mode {
            startup
        } else {
            with_database(startup, &self.config).await?
        };
        startup
            .runtime_health
            .set_allow_zero_listeners(self.allow_zero_listeners || self.api_only_mode);
        let (fatal_runtime_tx, mut fatal_runtime_rx) = mpsc::unbounded_channel::<String>();
        let mut listener_handles: Vec<JoinHandle<crate::Result<()>>> = Vec::new();
        let mut interceptor: Option<RunningInterceptor> = None;

        if !api_only_mode {
            if let Err(err) = init_distributed(
                &self.config,
                &startup.node_identity,
                &startup.runtime_health,
                fatal_runtime_tx.clone(),
                &mut startup.background_tasks,
            ) {
                startup.runtime_health.set_fatal_error(err.to_string());
                if let Some(shutdown_err) =
                    shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor)
                        .await
                {
                    tracing::warn!(
                        "Runtime shutdown reported an additional error after distributed startup failure: {}",
                        shutdown_err
                    );
                }
                return Err(err);
            }
        }
        if !api_only_mode {
            init_faketime(&self.config, &mut startup.background_tasks);
        }
        startup.runtime_health.set_api_disabled();
        if let Some(ref bind) = self.config.api_bind {
            if let Err(err) = start_api_server(
                bind,
                Arc::clone(&startup.flow_manager),
                Arc::clone(&startup.runtime_health),
                fatal_runtime_tx.clone(),
                &mut startup.background_tasks,
            )
            .await
            {
                startup.runtime_health.set_api_failed(err.to_string());
                if let Some(shutdown_err) =
                    shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor)
                        .await
                {
                    tracing::warn!(
                        "Runtime shutdown reported an additional error after API startup failure: {}",
                        shutdown_err
                    );
                }
                return Err(err);
            }
        }

        if self.intercept_enabled {
            startup.runtime_health.set_interceptor_starting();
            let interceptor_result = spawn_interceptor(
                &self.config,
                self.interface.clone(),
                self.output_override.clone(),
                Arc::clone(&startup.port_forward_table),
                Arc::clone(&startup.runtime_health),
                fatal_runtime_tx.clone(),
            )
            .await;

            match interceptor_result {
                Ok(Some(handle)) => {
                    interceptor = Some(handle);
                }
                Ok(None) if self.require_interceptor => {
                    let message = "Interception was requested but no interceptor could be started";
                    startup.runtime_health.set_interceptor_failed(message);
                    if let Some(shutdown_err) =
                        shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor)
                            .await
                    {
                        tracing::warn!(
                            "Runtime shutdown reported an additional error after interceptor startup failure: {}",
                            shutdown_err
                        );
                    }
                    return Err(crate::Error::Other(message.to_string()));
                }
                Ok(None) => {}
                Err(err) => {
                    startup
                        .runtime_health
                        .set_interceptor_failed(err.to_string());
                    if let Some(shutdown_err) =
                        shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor)
                            .await
                    {
                        tracing::warn!(
                            "Runtime shutdown reported an additional error after interceptor startup failure: {}",
                            shutdown_err
                        );
                    }
                    return Err(err);
                }
            }
        } else {
            startup.runtime_health.set_interceptor_disabled();
        }

        if !api_only_mode {
            let listener_result = spawn_listeners(
                &self.config,
                &startup,
                Arc::clone(&startup.runtime_health),
                fatal_runtime_tx.clone(),
            )
            .await;
            match listener_result {
                Ok(handles) => {
                    listener_handles = handles;
                }
                Err(err) => {
                    startup.runtime_health.set_fatal_error(err.to_string());
                    if let Some(shutdown_err) =
                        shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor)
                            .await
                    {
                        tracing::warn!(
                            "Runtime shutdown reported an additional error after listener startup failure: {}",
                            shutdown_err
                        );
                    }
                    return Err(err);
                }
            }
        }
        startup.runtime_health.mark_startup_complete();

        let task_count = listener_handles.len() + usize::from(interceptor.is_some());
        tracing::info!("Engine running with {} tasks", task_count);

        let shutdown_reason = wait_for_shutdown(stop_flag, &mut fatal_runtime_rx).await;

        let interceptor_shutdown_error =
            shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor).await;

        if let Some(err) = interceptor_shutdown_error {
            return Err(err);
        }

        if let ShutdownReason::Fatal(message) = shutdown_reason {
            return Err(crate::Error::Other(message));
        }

        Ok(())
    }
}

fn log_network_mode(config: &EngineConfig) {
    let mode = config.effective_network_mode();
    tracing::info!("Network mode: {:?}", mode);
    match mode {
        crate::config::NetworkMode::SingleHost => {
            tracing::info!("SingleHost mode: intercepting local traffic only");
        }
        crate::config::NetworkMode::MultiHost => {
            tracing::info!("MultiHost mode: acting as gateway for external hosts");
            if cfg!(not(target_os = "linux")) {
                tracing::warn!("MultiHost mode is only fully supported on Linux");
            }
        }
        _ => {}
    }
}

fn log_redirect_mode(config: &EngineConfig) {
    if config.redirect_all_traffic {
        if config.default_tcp_listener.is_some() || config.default_udp_listener.is_some() {
            tracing::info!(
                "RedirectAllTraffic enabled — unbound ports will route to default listeners"
            );
        } else {
            tracing::warn!(
                "redirect_all_traffic is enabled but no default_tcp_listener/default_udp_listener configured"
            );
        }
    }
}

fn has_spawnable_listeners(config: &EngineConfig) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener_should_spawn(config, listener))
}

fn validate_listener_presence(
    config: &EngineConfig,
    allow_zero_listeners: bool,
) -> crate::Result<()> {
    if allow_zero_listeners || has_spawnable_listeners(config) {
        return Ok(());
    }

    Err(crate::Error::Config(
        "No spawnable listeners remain after config expansion/filtering".into(),
    ))
}

enum PreparedListener {
    Tcp {
        name: String,
        listener: TcpListener,
        ctx: Arc<crate::listener_context::ListenerContext>,
        output_path: Option<PathBuf>,
    },
    Udp {
        name: String,
        socket: UdpSocket,
        bind_addr: std::net::IpAddr,
        ctx: Box<crate::listener_context::ListenerContext>,
        output_path: Option<PathBuf>,
    },
}

pub(super) fn listener_is_default_target(
    config: &EngineConfig,
    listener: &crate::config::ListenerConfig,
) -> bool {
    use nettrap_core::prelude::Protocol;

    match listener.protocol {
        Protocol::Tcp => config
            .default_tcp_listener
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(listener.name.as_str())),
        Protocol::Udp => config
            .default_udp_listener
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(listener.name.as_str())),
        _ => false,
    }
}

pub(super) fn listener_should_spawn(
    config: &EngineConfig,
    listener: &crate::config::ListenerConfig,
) -> bool {
    use nettrap_core::prelude::Protocol;

    if !listener.enabled {
        return false;
    }

    if listener.hidden && !listener_is_default_target(config, listener) {
        return false;
    }

    let is_tcp = listener.protocol == Protocol::Tcp;
    !config.is_port_blacklisted(listener.port, is_tcp)
}

async fn spawn_listeners(
    config: &EngineConfig,
    startup: &StartupContext,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
) -> crate::Result<Vec<JoinHandle<crate::Result<()>>>> {
    use nettrap_core::prelude::Protocol;

    let mut prepared = Vec::new();

    for listener in &config.listeners {
        let is_default_target = listener_is_default_target(config, listener);
        let should_spawn = listener_should_spawn(config, listener);

        if !should_spawn {
            if !listener.enabled {
                tracing::debug!("Listener {} disabled, skipping", listener.name);
            } else if listener.hidden && !is_default_target {
                tracing::info!(
                    "Listener {} registered as hidden (proxy-only) on port {}",
                    listener.name,
                    listener.port,
                );
            } else {
                tracing::debug!(
                    "Skipping listener {} on port {} (blacklisted or filtered)",
                    listener.name,
                    listener.port,
                );
            }
            continue;
        }

        runtime_health.register_listener(
            listener.name.clone(),
            format!("{:?}", listener.protocol),
            listener.port,
        );

        let is_tcp = listener.protocol == Protocol::Tcp;
        if listener.hidden {
            tracing::info!(
                "Starting hidden listener {} on port {} as default {} target",
                listener.name,
                listener.port,
                if is_tcp { "TCP" } else { "UDP" }
            );
        }

        tracing::info!(
            "Starting listener {} on port {} ({:?}){}",
            listener.name,
            listener.port,
            listener.protocol,
            if listener.use_ssl { " [SSL]" } else { "" }
        );

        let smtp_dir = startup
            .output_path
            .as_ref()
            .map(|p| p.parent().unwrap_or(p).join("smtp"));

        let listener_ctx = build_listener_context(listener, startup, smtp_dir)?;
        let bind_addr: std::net::IpAddr = listener.bind_address.parse().map_err(|err| {
            crate::Error::Config(format!(
                "Listener '{}' has invalid bind_address '{}': {}",
                listener.name, listener.bind_address, err
            ))
        })?;

        let output_path = startup.output_path.clone();
        let addr = std::net::SocketAddr::new(bind_addr, listener.port);

        match listener.protocol {
            Protocol::Udp => {
                let socket = UdpSocket::bind(addr).await.map_err(|err| {
                    let message = format!(
                        "Failed to bind UDP listener '{}' on {}: {}",
                        listener.name, addr, err
                    );
                    runtime_health.mark_listener_failed(&listener.name, message.clone());
                    crate::Error::Other(message)
                })?;
                let local_addr = socket.local_addr()?;
                runtime_health.mark_listener_running(&listener.name, local_addr.port());
                prepared.push(PreparedListener::Udp {
                    name: listener.name.clone(),
                    socket,
                    bind_addr,
                    ctx: Box::new(listener_ctx),
                    output_path,
                });
            }
            Protocol::Tcp => {
                let ctx = Arc::new(listener_ctx);
                let tcp_listener = TcpListener::bind(addr).await.map_err(|err| {
                    let message = format!(
                        "Failed to bind TCP listener '{}' on {}: {}",
                        listener.name, addr, err
                    );
                    runtime_health.mark_listener_failed(&listener.name, message.clone());
                    crate::Error::Other(message)
                })?;
                let local_addr = tcp_listener.local_addr()?;
                runtime_health.mark_listener_running(&listener.name, local_addr.port());
                prepared.push(PreparedListener::Tcp {
                    name: listener.name.clone(),
                    listener: tcp_listener,
                    ctx,
                    output_path,
                });
            }
            _ => {
                let message = format!(
                    "Unsupported protocol {:?} for listener {}",
                    listener.protocol, listener.name
                );
                runtime_health.mark_listener_failed(&listener.name, message.clone());
                return Err(crate::Error::Other(message));
            }
        }
    }

    if config.redirect_all_traffic {
        if let Some(ref default_tcp) = config.default_tcp_listener {
            tracing::info!(
                "RedirectAllTraffic: unbound TCP ports will use taste router (default: {})",
                default_tcp
            );
        }
    }

    let mut handles = Vec::with_capacity(prepared.len());
    for listener in prepared {
        match listener {
            PreparedListener::Udp {
                name,
                socket,
                bind_addr,
                ctx,
                output_path,
            } => {
                let runtime_health = Arc::clone(&runtime_health);
                let fatal_runtime_tx = fatal_runtime_tx.clone();
                handles.push(tokio::spawn(async move {
                    let result =
                        run_udp_listener(*ctx, socket, bind_addr, output_path.as_deref()).await;
                    let message = format!("UDP listener '{}' stopped unexpectedly", name);
                    match &result {
                        Ok(()) => {
                            runtime_health.mark_listener_stopped(&name);
                            runtime_health.set_fatal_error(message.clone());
                            let _ = fatal_runtime_tx.send(message);
                        }
                        Err(err) => {
                            let message = format!("UDP listener '{}' failed: {}", name, err);
                            runtime_health.mark_listener_failed(&name, message.clone());
                            let _ = fatal_runtime_tx.send(message);
                        }
                    }
                    result
                }));
            }
            PreparedListener::Tcp {
                name,
                listener,
                ctx,
                output_path,
            } => {
                let runtime_health = Arc::clone(&runtime_health);
                let fatal_runtime_tx = fatal_runtime_tx.clone();
                handles.push(tokio::spawn(async move {
                    let result = run_tcp_listener(ctx, listener, output_path.as_deref()).await;
                    let message = format!("TCP listener '{}' stopped unexpectedly", name);
                    match &result {
                        Ok(()) => {
                            runtime_health.mark_listener_stopped(&name);
                            runtime_health.set_fatal_error(message.clone());
                            let _ = fatal_runtime_tx.send(message);
                        }
                        Err(err) => {
                            let message = format!("TCP listener '{}' failed: {}", name, err);
                            runtime_health.mark_listener_failed(&name, message.clone());
                            let _ = fatal_runtime_tx.send(message);
                        }
                    }
                    result
                }));
            }
        }
    }

    Ok(handles)
}

async fn shutdown_listener_tasks(handles: Vec<JoinHandle<crate::Result<()>>>) {
    // Abort all running tasks first
    for handle in &handles {
        if !handle.is_finished() {
            handle.abort();
        }
    }

    // Then await all handles to ensure they've actually stopped
    for handle in handles {
        match handle.await {
            Ok(Err(err)) => {
                tracing::warn!("Listener task had error: {}", err);
            }
            Err(err) if !err.is_cancelled() => {
                tracing::warn!("Listener task panicked: {}", err);
            }
            _ => {}
        }
    }
}

async fn stop_runtime_tasks(
    startup: &mut StartupContext,
    listener_handles: Vec<JoinHandle<crate::Result<()>>>,
    interceptor: Option<RunningInterceptor>,
) -> Option<crate::Error> {
    shutdown_listener_tasks(listener_handles).await;

    let interceptor_shutdown_error = if let Some(interceptor) = interceptor {
        interceptor.shutdown().await.err()
    } else {
        None
    };

    if let Some(task) = startup.session_cleanup_task.take() {
        task.abort();
        let _ = task.await;
    }

    for task in &startup.background_tasks {
        task.abort();
    }
    for task in startup.background_tasks.drain(..) {
        let _ = task.await;
    }

    interceptor_shutdown_error
}

async fn shutdown_runtime(
    startup: &mut StartupContext,
    config: &EngineConfig,
    listener_handles: Vec<JoinHandle<crate::Result<()>>>,
    interceptor: Option<RunningInterceptor>,
) -> Option<crate::Error> {
    let interceptor_shutdown_error =
        stop_runtime_tasks(startup, listener_handles, interceptor).await;

    let shutdown_ctx = ShutdownContext::new(
        startup.output_path.clone(),
        startup.nbi_path.clone(),
        startup.pcap_writer.clone(),
        startup.database.clone(),
        Some(Arc::clone(&startup.nbi_collector)),
        startup.database_node_id.clone(),
        Some(startup.run_id.clone()),
    );
    execute_shutdown(&shutdown_ctx, config).await;

    interceptor_shutdown_error
}

enum ShutdownReason {
    Signal,
    StopFlag,
    Fatal(String),
}

async fn wait_for_shutdown(
    stop_flag: Option<std::path::PathBuf>,
    fatal_runtime_rx: &mut mpsc::UnboundedReceiver<String>,
) -> ShutdownReason {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if result.is_ok() {
                tracing::info!("Received Ctrl+C, shutting down...");
            }
            ShutdownReason::Signal
        }
        _ = watch_stop_flag(stop_flag) => {
            tracing::info!("Stop flag detected, shutting down...");
            ShutdownReason::StopFlag
        }
        fatal = fatal_runtime_rx.recv() => {
            let message = fatal.unwrap_or_else(|| "runtime component failed".to_string());
            tracing::warn!("Fatal runtime error: {}", message);
            ShutdownReason::Fatal(message)
        }
    }
}

async fn watch_stop_flag(path: Option<std::path::PathBuf>) {
    match path {
        Some(p) => loop {
            if p.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        },
        None => {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use nettrap_core::prelude::Protocol;

    use super::*;
    use crate::cli::RunArgs;

    #[test]
    fn cli_attribution_flag_does_not_disable_config_when_absent() {
        let mut config = EngineConfig::default();
        config.attribution_enabled = true;

        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(config.attribution_enabled);
    }

    #[test]
    fn handle_pcap_returns_explicit_not_implemented_error() {
        let args = crate::cli::PcapArgs {
            input: PathBuf::from("capture.pcap"),
            output: None,
            live: false,
        };

        let err = handle_pcap(&args, false).expect_err("pcap command should fail explicitly");

        assert!(err.to_string().contains("not implemented yet"));
    }

    #[test]
    fn handle_report_exports_jsonl_input() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!(
            "nettrap-report-input-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let output = dir.join(format!(
            "nettrap-report-output-{}.csv",
            uuid::Uuid::new_v4()
        ));
        let destination = crate::session::SessionDestination::unknown(8080);
        let event = crate::nbi::raw_nbi("raw", "127.0.0.1", 12345, &destination, 4, "74657374");
        fs::write(&input, format!("{}\n", event.to_json())).expect("write JSONL input");

        let args = crate::cli::ReportArgs {
            input: input.clone(),
            output: Some(output.clone()),
            format: None,
        };

        handle_report(&args).expect("report export should succeed");

        let csv = fs::read_to_string(&output).expect("report output should be readable");
        assert!(csv.contains("RAW"));
        assert!(csv.contains("127.0.0.1"));

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn finalize_after_cli_overrides_rejects_invalid_output_format() {
        let mut config = EngineConfig::default();
        config.output_format = "xml".to_string();

        let err = config
            .finalize_after_cli_overrides()
            .expect_err("invalid output format should be rejected");

        assert!(err.to_string().contains("unsupported output format 'xml'"));
    }

    #[test]
    fn cli_ports_are_renormalized_after_overrides() {
        let mut config = EngineConfig::default();
        config.listeners = vec![
            crate::config::ListenerConfig::new("cli_80", 443),
            crate::config::ListenerConfig::new("https", 8443),
        ];

        let args = RunArgs {
            interface: None,
            ports: vec![80, 443],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");
        config
            .finalize_listener_names()
            .expect("post-CLI listener names should normalize");

        let names: Vec<&str> = config
            .listeners
            .iter()
            .map(|listener| listener.name.as_str())
            .collect();
        assert_eq!(names, vec!["cli_80", "cli_80_80"]);
    }

    #[test]
    fn cli_ports_are_deduplicated_before_synthetic_listeners_are_added() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        let args = RunArgs {
            interface: None,
            ports: vec![80, 80, 81],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        let mut ports: Vec<u16> = config
            .listeners
            .iter()
            .map(|listener| listener.port)
            .collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![80, 81]);
    }

    #[test]
    fn cli_ports_create_synthetic_listener_when_existing_port_is_not_spawnable() {
        let mut config = EngineConfig::default();
        let mut hidden = crate::config::ListenerConfig::new("hidden_http", 80);
        hidden.hidden = true;
        config.listeners = vec![hidden];
        config
            .finalize_listener_names()
            .expect("listener names should normalize");

        let args = RunArgs {
            interface: None,
            ports: vec![80],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(
            config
                .listeners
                .iter()
                .any(|listener| listener.name == "cli_80")
        );
        assert!(
            config
                .listeners
                .iter()
                .any(|listener| listener.name == "hidden_http")
        );
    }

    #[test]
    fn cli_ports_override_global_port_blacklists_for_requested_ports() {
        let mut config = EngineConfig::default();
        config.listeners.clear();
        config.blacklist_ports_tcp = vec![80];

        let args = RunArgs {
            interface: None,
            ports: vec![80],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        assert!(config.blacklist_ports_tcp.is_empty());
        assert!(config.listeners.iter().any(|listener| listener.port == 80));
    }

    #[test]
    fn cli_ports_inherit_protocol_from_non_spawnable_listener() {
        let mut config = EngineConfig::default();
        let mut hidden_dns = crate::config::ListenerConfig::new("hidden_dns", 53);
        hidden_dns.protocol = Protocol::Udp;
        hidden_dns.hidden = true;
        hidden_dns.bind_address = "127.0.0.1".to_string();
        hidden_dns.use_ssl = true;
        config.listeners = vec![hidden_dns];

        let args = RunArgs {
            interface: None,
            ports: vec![53],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        apply_cli_overrides(&mut config, &args).expect("CLI overrides should apply");

        let synthetic = config
            .listeners
            .iter()
            .find(|listener| listener.name == "cli_53")
            .expect("synthetic listener should be created");
        assert_eq!(synthetic.protocol, Protocol::Udp);
        assert_eq!(synthetic.bind_address, "127.0.0.1");
        assert!(synthetic.use_ssl);
        assert!(synthetic.enabled);
        assert!(!synthetic.hidden);
    }

    #[test]
    fn cli_ports_reject_ambiguous_protocol_inheritance() {
        let mut config = EngineConfig::default();
        let mut hidden_tcp = crate::config::ListenerConfig::new("hidden_tcp", 5353);
        hidden_tcp.protocol = Protocol::Tcp;
        hidden_tcp.hidden = true;
        let mut hidden_udp = crate::config::ListenerConfig::new("hidden_udp", 5353);
        hidden_udp.protocol = Protocol::Udp;
        hidden_udp.hidden = true;
        config.listeners = vec![hidden_tcp, hidden_udp];

        let args = RunArgs {
            interface: None,
            ports: vec![5353],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let err = apply_cli_overrides(&mut config, &args)
            .expect_err("mixed protocol listeners should be rejected");

        assert!(err.to_string().contains("use both TCP and UDP"));
    }

    #[test]
    fn load_api_config_ignores_invalid_listener_bind_address() {
        let path =
            std::env::temp_dir().join(format!("nettrap-api-raw-{}.toml", std::process::id()));
        let mut config = EngineConfig::default();
        config.database.pool_size = 0;
        config.attribution_timeout_ms = 0;
        config.listeners =
            vec![crate::config::ListenerConfig::new("http", 80).with_bind_address("not-an-ip")];
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), None)
            .expect("API-only config loading should ignore listener bind validation");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.listeners.len(), 1);
        assert_eq!(loaded.listeners[0].bind_address, "not-an-ip");
        assert_eq!(loaded.database.pool_size, 1);
        assert_eq!(loaded.attribution_timeout_ms, 100);
    }

    #[test]
    fn handle_config_check_takes_priority_over_explicit_config_output() {
        let config_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-priority-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let output_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-priority-out-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let serialized = toml::to_string(&EngineConfig::default()).expect("serialize config");
        fs::write(&config_path, serialized).expect("write config");

        let args = crate::cli::ConfigArgs {
            output: Some(output_path.clone()),
            check: true,
            defaults: false,
        };

        handle_config(&args, Some(config_path.clone())).expect("config check should succeed");

        assert!(!output_path.exists());

        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_file(&output_path);
    }

    #[test]
    fn handle_config_check_returns_error_for_invalid_explicit_config() {
        let config_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-invalid-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let mut config = EngineConfig::default();
        config.api_bind = Some(" ".into());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&config_path, serialized).expect("write config");

        let args = crate::cli::ConfigArgs {
            output: None,
            check: true,
            defaults: false,
        };

        let err = handle_config(&args, Some(config_path.clone()))
            .expect_err("invalid config check should return error");

        assert!(err.to_string().contains("Configuration validation failed"));

        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn load_api_config_overrides_invalid_api_bind_from_config() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-api-override-bind-{}.toml",
            std::process::id()
        ));
        let mut config = EngineConfig::default();
        config.api_bind = Some("not-a-socket".to_string());
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = load_api_config(Some(path.clone()), Some("127.0.0.1:18888"))
            .expect("API bind override should be applied");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.api_bind.as_deref(), Some("127.0.0.1:18888"));
    }

    #[test]
    fn check_config_paths_returns_error_if_any_file_is_invalid() {
        let valid_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-valid-{}.toml",
            uuid::Uuid::new_v4()
        ));
        let invalid_path = std::env::temp_dir().join(format!(
            "nettrap-config-check-invalid-list-{}.toml",
            uuid::Uuid::new_v4()
        ));

        fs::write(
            &valid_path,
            toml::to_string(&EngineConfig::default()).expect("serialize config"),
        )
        .expect("write valid config");

        let mut invalid = EngineConfig::default();
        invalid.api_bind = Some("".into());
        fs::write(
            &invalid_path,
            toml::to_string(&invalid).expect("serialize invalid config"),
        )
        .expect("write invalid config");

        let err = check_config_paths(&[valid_path.clone(), invalid_path.clone()])
            .expect_err("mixed validity should return error");

        assert!(err.to_string().contains("1 file(s)"));

        let _ = fs::remove_file(&valid_path);
        let _ = fs::remove_file(&invalid_path);
    }

    #[test]
    fn allow_zero_listeners_does_not_enable_api_only_mode() {
        let engine = Engine::new(EngineConfig::default(), false, None, None, false, true);

        assert!(engine.allow_zero_listeners);
        assert!(!engine.api_only_mode);
    }

    #[test]
    fn api_only_engine_uses_explicit_mode() {
        let engine = Engine::api_only(EngineConfig::default());

        assert!(engine.allow_zero_listeners);
        assert!(engine.api_only_mode);
        assert!(!engine.intercept_enabled);
    }

    #[tokio::test]
    async fn api_only_engine_does_not_initialize_faketime() {
        crate::faketime::set_delta(0);

        let mut config = EngineConfig::default();
        config.faketime.enabled = true;
        config.faketime.init_delta = 3600;

        let stop_flag =
            std::env::temp_dir().join(format!("nettrap-api-stop-{}", uuid::Uuid::new_v4()));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        engine
            .run(Some(stop_flag.clone()))
            .await
            .expect("api-only engine should stop cleanly");

        assert_eq!(crate::faketime::get_delta(), 0);

        let _ = fs::remove_file(&stop_flag);
    }

    #[tokio::test]
    async fn api_only_engine_ignores_distributed_runtime_configuration() {
        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
        config.distributed.health_bind = Some("127.0.0.1:0".into());
        config.distributed.metrics_bind = Some("127.0.0.1:0".into());
        config
            .distributed
            .event_sinks
            .push(crate::config::EventSinkConfig {
                sink_type: "bogus".into(),
                target: "127.0.0.1:1".into(),
                auth: None,
                batch_size: 1,
                flush_interval_ms: 1000,
                request_timeout_ms: 1000,
            });

        let stop_flag = std::env::temp_dir().join(format!(
            "nettrap-api-distributed-stop-{}",
            uuid::Uuid::new_v4()
        ));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        engine
            .run(Some(stop_flag.clone()))
            .await
            .expect("api-only engine should ignore distributed runtime config");

        let _ = fs::remove_file(&stop_flag);
    }

    #[tokio::test]
    async fn api_only_engine_ignores_invalid_database_backend() {
        let mut config = EngineConfig::default();
        config.database.backend = "postgres".to_string();
        config.database.postgres_url = Some("postgres://invalid:bad".to_string());

        let stop_flag =
            std::env::temp_dir().join(format!("nettrap-api-db-stop-{}", uuid::Uuid::new_v4()));
        fs::write(&stop_flag, b"stop").expect("write stop flag");

        let engine = Engine::api_only(config);
        engine
            .run(Some(stop_flag.clone()))
            .await
            .expect("api-only engine should ignore invalid DB backend");

        let _ = fs::remove_file(&stop_flag);
    }

    #[test]
    fn cli_ports_reject_ambiguous_listener_clone_settings() {
        let mut config = EngineConfig::default();
        let mut hidden_a = crate::config::ListenerConfig::new("hidden_a", 8080);
        hidden_a.hidden = true;
        hidden_a.bind_address = "127.0.0.1".to_string();
        let mut hidden_b = crate::config::ListenerConfig::new("hidden_b", 8080);
        hidden_b.hidden = true;
        hidden_b.bind_address = "127.0.0.2".to_string();
        config.listeners = vec![hidden_a, hidden_b];

        let args = RunArgs {
            interface: None,
            ports: vec![8080],
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let err = apply_cli_overrides(&mut config, &args)
            .expect_err("incompatible base listeners should be rejected");

        assert!(err.to_string().contains("incompatible settings"));
    }

    #[test]
    fn hidden_default_listener_is_considered_spawnable() {
        let mut config = EngineConfig::default();
        let mut listener = crate::config::ListenerConfig::new("http-default", 8080);
        listener.hidden = true;
        config.listeners = vec![listener.clone()];
        config.default_tcp_listener = Some(listener.name.to_uppercase());

        assert!(listener_is_default_target(&config, &listener));
        assert!(listener_should_spawn(&config, &listener));
    }

    #[test]
    fn validate_listener_presence_rejects_empty_runtime_in_run_mode() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        let err = validate_listener_presence(&config, false).unwrap_err();
        assert!(err.to_string().contains("No spawnable listeners"));
    }

    #[test]
    fn validate_listener_presence_allows_api_only_mode_without_listeners() {
        let mut config = EngineConfig::default();
        config.listeners.clear();

        validate_listener_presence(&config, true).expect("api-only mode should be allowed");
    }

    #[tokio::test]
    async fn build_engine_requires_interceptor_when_requested() {
        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: true,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let engine = build_engine(&args, false, None)
            .await
            .expect("engine should build");

        assert!(engine.intercept_enabled);
        assert!(engine.require_interceptor);
    }

    #[tokio::test]
    async fn build_engine_keeps_interceptor_optional_when_not_requested() {
        let args = RunArgs {
            interface: None,
            ports: Vec::new(),
            attribution: false,
            intercept: false,
            emulate: false,
            output: None,
            pcap: false,
            pcap_path: None,
            verbose_flows: false,
            log_level: None,
            json_output: false,
            report_format: None,
        };

        let engine = build_engine(&args, false, None)
            .await
            .expect("engine should build");

        assert!(!engine.intercept_enabled);
        assert!(!engine.require_interceptor);
    }
}
