use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::cli::Commands;
use crate::config::EngineConfig;
use crate::engine::interceptor::{RunningInterceptor, spawn_interceptor};
use crate::engine::shutdown::{ShutdownContext, execute_shutdown};
use crate::engine::startup::{
    StartupContext, build_listener_context, create_startup_context, init_distributed,
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
            let mut config = load_config(config_path)?;
            config.expand_listeners();
            config.api_bind = Some(args.bind.clone());

            let engine = Engine::new(config, true, None, None, true);
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
            crate::mkcert::install_mkcert().map_err(|e| crate::Error::Other(e))
        }
        crate::cli::TlsCommands::Install => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            crate::mkcert::install_ca().map_err(|e| crate::Error::Other(e))
        }
        crate::cli::TlsCommands::Generate(gen_args) => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into(),
                ));
            }
            let hosts: Vec<&str> = gen_args.hostnames.iter().map(|s| s.as_str()).collect();
            let (cert, key) = crate::mkcert::generate_cert(&hosts, &gen_args.output_dir)
                .map_err(|e| crate::Error::Other(e))?;
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
    config.expand_listeners();

    apply_cli_overrides(&mut config, args);

    Ok(Engine::new(
        config,
        args.intercept,
        args.interface.clone(),
        args.output.clone(),
        args.intercept,
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

    Ok(EngineConfig::default())
}

fn apply_cli_overrides(config: &mut EngineConfig, args: &crate::cli::RunArgs) {
    if !args.ports.is_empty() {
        // Keep configured listeners on CLI-specified ports, add cli_ listeners
        // for any ports not already covered by config
        let existing_ports: std::collections::HashSet<u16> = config
            .listeners
            .iter()
            .map(|l| l.port)
            .collect();
        for port in &args.ports {
            if !existing_ports.contains(port) {
                config.listeners.push(crate::config::ListenerConfig::new(
                    format!("cli_{}", port),
                    *port,
                ));
            }
        }
        // Only keep listeners whose port is in the CLI list
        config.listeners.retain(|l| args.ports.contains(&l.port));
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

    let config = if let Some(ref path) = config_path {
        EngineConfig::from_file(path)?
    } else if args.check {
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

        for file in files {
            match EngineConfig::from_file(&file) {
                Ok(_) => println!("✓ {} is valid", file.display()),
                Err(e) => println!("✗ {} is invalid: {}", file.display(), e),
            }
        }
        return Ok(());
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

fn handle_pcap(args: &crate::cli::PcapArgs, _verbose: bool) -> crate::Result<()> {
    println!("Processing PCAP file: {}", args.input.display());
    Ok(())
}

fn handle_report(args: &crate::cli::ReportArgs) -> crate::Result<()> {
    println!("Generating report from: {}", args.input.display());
    Ok(())
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
    ) -> Self {
        Self {
            config,
            intercept_enabled,
            require_interceptor,
            interface,
            output_override,
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub async fn run(&self, stop_flag: Option<std::path::PathBuf>) -> crate::Result<()> {
        tracing::info!("Starting NetTrap engine...");

        log_network_mode(&self.config);
        log_redirect_mode(&self.config);

        init_windows_network(&self.config);
        init_windows_ca_trust(&self.config);

        let startup = create_startup_context(&self.config, self.output_override.clone())?;
        let mut startup = with_database(startup, &self.config).await?;
        let (fatal_runtime_tx, mut fatal_runtime_rx) = mpsc::unbounded_channel::<String>();
        let mut listener_handles: Vec<JoinHandle<crate::Result<()>>> = Vec::new();
        let mut interceptor: Option<RunningInterceptor> = None;

        if let Err(err) = init_distributed(
            &self.config,
            &startup.node_identity,
            &startup.runtime_health,
            fatal_runtime_tx.clone(),
            &mut startup.background_tasks,
        ) {
            startup.runtime_health.set_fatal_error(err.to_string());
            if let Some(shutdown_err) =
                shutdown_runtime(&mut startup, &self.config, listener_handles, interceptor).await
            {
                tracing::warn!(
                    "Runtime shutdown reported an additional error after distributed startup failure: {}",
                    shutdown_err
                );
            }
            return Err(err);
        }
        init_faketime(&self.config, &mut startup.background_tasks);
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
        ctx: crate::listener_context::ListenerContext,
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

        let listener_ctx = build_listener_context(listener, startup, smtp_dir);
        let bind_addr: std::net::IpAddr = listener
            .bind_address
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

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
                    ctx: listener_ctx,
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
                        run_udp_listener(ctx, socket, bind_addr, output_path.as_deref()).await;
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

        apply_cli_overrides(&mut config, &args);

        assert!(config.attribution_enabled);
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
}
