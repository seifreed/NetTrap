use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::cli::Commands;
use crate::config::EngineConfig;
use crate::listener_runtime::ConnectionDedup;
use crate::utils::{log_event, dump_http_post, extract_http_host, extract_http_method, extract_http_path, build_http_response_with_fakefile};

pub async fn handle_command(
    command: Commands,
    verbose: bool,
    config_path: Option<std::path::PathBuf>,
    stop_flag: Option<std::path::PathBuf>,
) -> crate::Result<()> {
    match command {
        Commands::Run(args) => {
            let engine = run_engine(&args, verbose, config_path).await?;
            engine.run(stop_flag).await
        }
        Commands::Config(args) => handle_config(&args, config_path),
        Commands::Pcap(args) => handle_pcap(&args, verbose),
        Commands::Report(args) => handle_report(&args),
        Commands::Status(args) => handle_status(&args),
        Commands::Test(args) => handle_test(&args),
        Commands::Tui(_args) => {
            tracing::info!("TUI mode not yet fully implemented - use 'nettrap report' for HTML reports");
            Ok(())
        }
        Commands::Api(_args) => {
            tracing::info!("API server not yet fully implemented");
            Ok(())
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
            crate::mkcert::install_mkcert()
                .map_err(|e| crate::Error::Other(e))
        }
        crate::cli::TlsCommands::Install => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into()
                ));
            }
            crate::mkcert::install_ca()
                .map_err(|e| crate::Error::Other(e))
        }
        crate::cli::TlsCommands::Generate(gen_args) => {
            if !crate::mkcert::is_mkcert_installed() {
                return Err(crate::Error::Other(
                    "mkcert is not installed. Run 'nettrap tls install-mkcert' first.".into()
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

async fn run_engine(
    args: &crate::cli::RunArgs,
    _verbose: bool,
    config_path: Option<std::path::PathBuf>,
) -> crate::Result<Engine> {
    let mut config = if let Some(path) = config_path {
        EngineConfig::from_file(&path)?
    } else {
        let default_path = std::path::Path::new("/etc/nettrap/config.toml");
        if default_path.exists() {
            EngineConfig::from_file(default_path)?
        } else {
            EngineConfig::default()
        }
    };

    // Expand port ranges into individual listeners
    config.expand_listeners();

    if !args.ports.is_empty() {
        config.listeners = args
            .ports
            .iter()
            .enumerate()
            .map(|(i, port)| crate::config::ListenerConfig::new(format!("listener_{}", i), *port))
            .collect();
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

    config.attribution_enabled = args.attribution;

    if let Some(ref fmt) = args.report_format {
        config.output_format = fmt.clone();
    }

    Ok(Engine::new(
        config,
        args.intercept,
        args.interface.clone(),
        args.output.clone(),
    ))
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
            .filter(|e| e.path().extension().map(|ext| ext == "toml").unwrap_or(false))
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

/// Resolve special server name escapes for SMTP/IRC/POP3 banners
fn resolve_service_name(input: &str) -> String {
    if input == "!hostname" || input == "!gethostname" {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "nettrap.local".to_string())
    } else if input == "!random" {
        use rand::Rng;
        let mut rng = rand::rng();
        let len = rng.random_range(5..=12);
        let name: String = (0..len).map(|_| rng.random_range(b'a'..=b'z') as char).collect();
        format!("{}.local", name)
    } else {
        input.to_string()
    }
}

pub struct Engine {
    config: EngineConfig,
    intercept_enabled: bool,
    _interface: Option<String>,
    output_override: Option<PathBuf>,
}

impl Engine {
    pub fn new(
        config: EngineConfig,
        intercept_enabled: bool,
        interface: Option<String>,
        output_override: Option<PathBuf>,
    ) -> Self {
        Self {
            config,
            intercept_enabled,
            _interface: interface,
            output_override,
        }
    }

    pub async fn run(&self, stop_flag: Option<std::path::PathBuf>) -> crate::Result<()> {
        tracing::info!("Starting NetTrap engine...");

        // ── Wire NetworkMode (change #10) ────────────────────────────────
        let mode = self.config.effective_network_mode();
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

        // ── Wire redirect_all_traffic (change #9) ───────────────────────
        if self.config.redirect_all_traffic {
            if self.config.default_tcp_listener.is_some() || self.config.default_udp_listener.is_some() {
                tracing::info!("RedirectAllTraffic enabled — unbound ports will route to default listeners");
            } else {
                tracing::warn!("redirect_all_traffic is enabled but no default_tcp_listener/default_udp_listener configured");
            }
        }

        // Initialize TLS CA if configured or generate one
        let ca = self.init_tls_ca()?;

        // ── Windows network setup (#9) ──────────────────────────────────
        if cfg!(target_os = "windows") {
            if self.config.has_debug_flag("FIXGATEWAY") {
                crate::windows_setup::fix_gateway();
            }
            if self.config.has_debug_flag("FIXDNS") {
                crate::windows_setup::fix_dns();
            }
            if self.config.has_debug_flag("STOPDNSSERVICE") {
                crate::windows_setup::stop_dns_service();
            }
        }

        // ── CA auto-trust (#10) ─────────────────────────────────────────
        if let Some(ref dir) = self.config.tls_cert_dir {
            let cert_path = format!("{}/ca.crt", dir);
            if std::path::Path::new(&cert_path).exists() {
                crate::windows_setup::install_ca_trust(&cert_path);
            }
        }

        // ── Wire protocol router / taste system (change #1) ─────────────
        use nettrap_proxy::{
            ProtocolRouter, DnsTaste, HttpTaste, TlsTaste, SmtpTaste,
            FtpTaste, Pop3Taste, IrcTaste, TftpTaste, QuicTaste, RawTaste,
            TelnetTaste, SshTaste, SmbTaste, RdpTaste, RedisTaste, MysqlTaste,
            LdapTaste, MqttTaste, SnmpTaste, SocksTaste, MemcachedTaste,
            NknTaste, PostgresTaste, SipTaste, UpnpTaste, NtpTaste, CoapTaste,
            FingerTaste, IdentTaste, DaytimeTaste, TimeTaste, ChargenTaste,
            QuotdTaste, SyslogRecvTaste, DummyTaste,
        };

        let router = Arc::new(
            ProtocolRouter::new()
                .with_default_tcp(self.config.default_tcp_listener.clone().unwrap_or_default())
                .with_default_udp(self.config.default_udp_listener.clone().unwrap_or_default()),
        );
        router.register("dns", Box::new(DnsTaste), false);
        router.register("http", Box::new(HttpTaste), false);
        router.register("tls", Box::new(TlsTaste), false);
        router.register("smtp", Box::new(SmtpTaste), false);
        router.register("ftp", Box::new(FtpTaste), false);
        router.register("pop3", Box::new(Pop3Taste), false);
        router.register("irc", Box::new(IrcTaste), false);
        router.register("tftp", Box::new(TftpTaste), false);
        router.register("quic", Box::new(QuicTaste), false);
        router.register("telnet", Box::new(TelnetTaste), false);
        router.register("ssh", Box::new(SshTaste), false);
        router.register("smb", Box::new(SmbTaste), false);
        router.register("rdp", Box::new(RdpTaste), false);
        router.register("redis", Box::new(RedisTaste), false);
        router.register("mysql", Box::new(MysqlTaste), false);
        router.register("ldap", Box::new(LdapTaste), false);
        router.register("mqtt", Box::new(MqttTaste), false);
        router.register("snmp", Box::new(SnmpTaste), false);
        router.register("socks", Box::new(SocksTaste), false);
        router.register("memcached", Box::new(MemcachedTaste), false);
        router.register("nkn", Box::new(NknTaste), false);
        router.register("postgres", Box::new(PostgresTaste), false);
        router.register("sip", Box::new(SipTaste), false);
        router.register("upnp", Box::new(UpnpTaste), false);
        router.register("ntp", Box::new(NtpTaste), false);
        router.register("coap", Box::new(CoapTaste), false);
        router.register("finger", Box::new(FingerTaste), false);
        router.register("ident", Box::new(IdentTaste), false);
        router.register("daytime", Box::new(DaytimeTaste), false);
        router.register("time", Box::new(TimeTaste), false);
        router.register("chargen", Box::new(ChargenTaste), false);
        router.register("quotd", Box::new(QuotdTaste), false);
        router.register("syslogrecv", Box::new(SyslogRecvTaste), false);
        router.register("dummy", Box::new(DummyTaste), false);
        router.register("raw", Box::new(RawTaste), false);

        tracing::debug!("Protocol router initialised with {} handlers", router.handler_count());

        // ── Wire attribution engine (change #4) ─────────────────────────
        let attribution = if self.config.attribution_enabled {
            Some(Arc::new(nettrap_attribution::AttributionEngine::with_timeout(
                std::time::Duration::from_millis(self.config.attribution_timeout_ms),
            )))
        } else {
            None
        };

        // ── Wire PCAP writer (change #5) ────────────────────────────────
        let pcap_writer = if self.config.pcap_enabled {
            let path = self.config.pcap_path.clone().unwrap_or_else(|| {
                let prefix = self.config.pcap_prefix.as_deref().unwrap_or("packets");
                format!("{}_{}.pcap", prefix, chrono::Utc::now().format("%Y%m%d_%H%M%S"))
            });
            let writer = Arc::new(nettrap_pcap::PcapWriter::new(&path));
            writer.open().map_err(|e| crate::Error::Other(format!("PCAP open failed: {}", e)))?;
            tracing::info!("PCAP recording to {}", path);
            Some(writer)
        } else {
            None
        };

        let mut handles: Vec<JoinHandle<crate::Result<()>>> = Vec::new();

        let output_path: Option<PathBuf> = self
            .output_override
            .clone()
            .or_else(|| self.config.output_path.clone().map(PathBuf::from));

        if self.intercept_enabled {
            if let Some(handle) = self.spawn_interceptor_task()? {
                handles.push(handle);
            }
        }

        // ── Wire debug flags for hexdump (change #8) ────────────────────
        let log_hexdump = self.config.log_hexdump || self.config.has_debug_flag("HEXDUMP");
        let http_post_dump_dir = self.config.http_post_dump_dir.clone();

        // ── Wire NBI collector ────────────────────────────────────────────
        let nbi_path = output_path.as_ref().map(|p| {
            let stem = p.file_stem().unwrap_or_default().to_string_lossy();
            p.with_file_name(format!("{}_nbi.jsonl", stem))
        });
        let nbi_path_for_report = nbi_path.clone();

        // ── Wire distributed features (all optional) ─────────────────────
        let node_identity = Arc::new(crate::distributed::NodeIdentity::generate(
            self.config.distributed.node_region.clone(),
            self.config.distributed.node_tags.clone(),
        ));

        if self.config.distributed.enabled {
            tracing::info!("Distributed mode enabled — node_id: {}", node_identity.node_id);
        }

        // Start health/metrics server if configured
        if let Some(ref health_bind) = self.config.distributed.health_bind {
            let bind = health_bind.clone();
            let node = Arc::clone(&node_identity);
            tokio::spawn(async move {
                crate::distributed::run_health_server(bind, node).await;
            });
        }

        // Start heartbeat if configured
        if let Some(ref control_url) = self.config.distributed.control_plane_url {
            let url = control_url.clone();
            let token = self.config.distributed.control_plane_token.clone();
            let node = Arc::clone(&node_identity);
            let interval = self.config.distributed.heartbeat_interval_secs;
            if interval > 0 {
                tokio::spawn(async move {
                    crate::distributed::run_heartbeat(url, token, node, interval).await;
                });
            }
        }

        // Build event fanout for distributed sinks
        let event_fanout = Arc::new(crate::distributed::build_event_fanout(&self.config.distributed));

        // Initialize database storage if configured
        let mut db_config = self.config.database.clone();
        db_config.node_id = Some(node_identity.node_id.clone());
        let database = crate::database::init_database(&db_config).await;
        let database = database.map(Arc::new);

        let mut nbi_collector = crate::nbi::NbiCollector::new(nbi_path).with_fanout(event_fanout);
        if let Some(ref db) = database {
            nbi_collector = nbi_collector.with_database(Arc::clone(db));
        }
        let nbi_collector = Arc::new(nbi_collector);

        // Wire session tracker
        let session_tracker = Arc::new(crate::session::SessionTracker::new());

        // Wire port forward table
        let port_forward_table = Arc::new(crate::session::PortForwardTable::new());

        // Global process filter lists for ListenerContext
        let global_process_whitelist = self.config.global_process_whitelist.clone();
        let global_process_blacklist = self.config.global_process_blacklist.clone();

        for listener in &self.config.listeners {
            if !listener.enabled {
                continue;
            }

            // ── Wire hidden listeners (change #7) ───────────────────────
            if listener.hidden {
                tracing::info!(
                    "Listener {} registered as hidden (proxy-only) on port {}",
                    listener.name,
                    listener.port,
                );
                // Register with router but don't start a TCP/UDP listener
                continue;
            }

            // Check global port blacklist
            let is_tcp = listener.protocol == nettrap_core::prelude::Protocol::Tcp;
            if self.config.is_port_blacklisted(listener.port, is_tcp) {
                tracing::debug!("Port {} blacklisted, skipping listener {}", listener.port, listener.name);
                continue;
            }

            tracing::info!(
                "Starting listener {} on port {} ({:?}){}",
                listener.name,
                listener.port,
                listener.protocol,
                if listener.use_ssl { " [SSL]" } else { "" }
            );

            let name = listener.name.clone();
            let port = listener.port;
            let protocol = listener.protocol;
            let bind_addr: std::net::IpAddr = listener
                .bind_address
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let out = output_path.clone();
            let banner = listener.banner.clone();
            let webroot = listener.webroot.clone();
            let ftproot = listener.ftproot.clone();
            let tftproot = listener.tftproot.clone();
            let execute_cmd = listener.execute_cmd.clone();
            let use_ssl = listener.use_ssl;
            let dump_http_posts = listener.dump_http_posts;
            let dump_prefix = listener.dump_http_posts_prefix.clone()
                .or_else(|| http_post_dump_dir.clone());
            let timeout_ms = listener.timeout_ms;
            let host_whitelist = listener.host_whitelist.clone();
            let host_blacklist = listener.host_blacklist.clone();
            let ca_clone = ca.clone();
            let custom_response = listener.custom_response.clone();
            let response_delay_ms = listener.response_delay_ms;

            let custom_response_config = listener.custom_response.as_ref().map(|cr| {
                crate::custom_response::CustomResponseConfig::parse(cr)
            });
            let nbi_collector_clone = Arc::clone(&nbi_collector);

            let pasv_ports = listener.pasv_ports.clone();
            let server_version = listener.server_version.clone();
            let dns_response_mode = listener.dns_response_mode.clone();
            let dns_response_ip = listener.dns_response_ip.clone();
            let dns_response_mx = listener.dns_response_mx.clone();
            let dns_response_txt = listener.dns_response_txt.clone();
            let dns_nxdomains = listener.dns_nxdomains;
            let smtp_dir = self.config.smtp_dir.as_ref().map(|s| PathBuf::from(s));

            let process_filter = crate::process_filter::ProcessFilter::build(
                global_process_whitelist.clone(),
                global_process_blacklist.clone(),
                listener.process_whitelist.clone(),
                listener.process_blacklist.clone(),
            );

            let listener_ctx = ListenerContext {
                name: name.clone(),
                port,
                banner,
                webroot,
                ftproot,
                tftproot,
                execute_cmd,
                use_ssl,
                dump_http_posts,
                dump_prefix,
                timeout_ms,
                log_hexdump,
                process_filter,
                host_whitelist,
                host_blacklist,
                ca: ca_clone,
                // New fields
                router: Arc::clone(&router),
                attribution: attribution.clone(),
                pcap_writer: pcap_writer.clone(),
                response_delay_ms,
                custom_response,
                nbi_collector: nbi_collector_clone,
                session_tracker: Arc::clone(&session_tracker),
                custom_response_config,
                server_version,
                dns_response_mode,
                dns_response_ip,
                dns_response_mx,
                dns_response_txt,
                dns_nxdomains,
                pasv_ports,
                connection_dedup: Arc::new(ConnectionDedup::new()),
                port_forward_table: Arc::clone(&port_forward_table),
                max_connections: listener.max_connections,
                banner_delay_ms: listener.banner_delay_ms,
                smtp_dir,
            };

            match protocol {
                nettrap_core::prelude::Protocol::Udp => {
                    let handle = tokio::spawn(async move {
                        run_udp_listener(listener_ctx, bind_addr, out.as_deref()).await
                    });
                    handles.push(handle);
                }
                nettrap_core::prelude::Protocol::Tcp => {
                    let ctx = Arc::new(listener_ctx);
                    let handle = tokio::spawn(async move {
                        run_tcp_listener(ctx, bind_addr, out.as_deref()).await
                    });
                    handles.push(handle);
                }
                _ => {
                    tracing::warn!(
                        "Unsupported protocol {:?} for listener {}",
                        protocol,
                        name
                    );
                }
            }
        }

        // ── Wire redirect_all_traffic real implementation (#15) ─────────
        if self.config.redirect_all_traffic {
            if let Some(ref default_tcp) = self.config.default_tcp_listener {
                tracing::info!("RedirectAllTraffic: unbound TCP ports will use taste router (default: {})", default_tcp);
                // The NFQUEUE/iptables handles actual redirection
                // The taste router handles protocol detection for arriving traffic
            }
        }

        // ── Wire FakeTime mode ───────────────────────────────────────────
        if self.config.faketime.enabled {
            crate::faketime::set_delta(self.config.faketime.init_delta);
            tracing::info!("FakeTime mode enabled — initial delta: {} seconds", self.config.faketime.init_delta);
            let ft_config = self.config.faketime.clone();
            tokio::spawn(async move {
                crate::faketime::run_auto_increment(ft_config).await;
            });
        }

        tracing::info!("Engine running with {} tasks", handles.len());

        // Wait for shutdown signal
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                tracing::info!("Received Ctrl+C, shutting down...");
            }
            _ = watch_stop_flag(stop_flag) => {
                tracing::info!("Stop flag detected, shutting down...");
            }
        }

        // ── Windows network restoration (#9) ──────────────────────────
        if cfg!(target_os = "windows") {
            if self.config.has_debug_flag("FIXDNS") {
                crate::windows_setup::restore_dns();
            }
            if self.config.has_debug_flag("STOPDNSSERVICE") {
                crate::windows_setup::start_dns_service();
            }
        }

        // Print database stats on shutdown
        if let Some(ref db) = database {
            match db.stats().await {
                Ok(stats) => stats.print_summary(),
                Err(e) => tracing::warn!("Failed to get DB stats: {}", e),
            }
            db.close().await;
        }

        // Print NBI summary to console before report generation
        if let Some(ref nbi_path) = nbi_path_for_report {
            crate::nbi::print_summary(nbi_path);
        }

        // Generate NBI HTML report on shutdown
        if let Some(ref nbi_path) = nbi_path_for_report {
            let html_path = nbi_path.with_extension("html");
            match crate::nbi::NbiCollector::generate_html_report(nbi_path, &html_path, &self.config.report_language) {
                Ok(()) => tracing::info!("NBI HTML report generated: {}", html_path.display()),
                Err(e) => tracing::warn!("Failed to generate NBI report: {}", e),
            }
        }

        // Export NBI in configured and additional formats on shutdown
        if let Some(ref nbi_path) = nbi_path_for_report {
            let events = crate::output::load_nbis_from_jsonl(nbi_path);
            if !events.is_empty() {
                // Determine output format from config
                let format = crate::output::OutputFormat::from_str(&self.config.output_format);

                // Export in configured format if different from JSONL (already written by NbiCollector)
                if format != crate::output::OutputFormat::Jsonl {
                    let export_path = nbi_path.with_extension(format.extension());
                    match crate::output::export_nbis(&events, format, &export_path) {
                        Ok(()) => tracing::info!("NBI exported as {}: {}", self.config.output_format, export_path.display()),
                        Err(e) => tracing::warn!("Failed to export NBI as {}: {}", self.config.output_format, e),
                    }
                }

                // Also generate SARIF if not already the primary format
                if format != crate::output::OutputFormat::Sarif {
                    let sarif_path = nbi_path.with_extension("sarif.json");
                    match crate::output::export_nbis(&events, crate::output::OutputFormat::Sarif, &sarif_path) {
                        Ok(()) => tracing::info!("SARIF report: {}", sarif_path.display()),
                        Err(e) => tracing::warn!("Failed to generate SARIF: {}", e),
                    }
                }

                // Also generate CSV always
                if format != crate::output::OutputFormat::Csv {
                    let csv_path = nbi_path.with_extension("csv");
                    match crate::output::export_nbis(&events, crate::output::OutputFormat::Csv, &csv_path) {
                        Ok(()) => tracing::info!("CSV report: {}", csv_path.display()),
                        Err(e) => tracing::warn!("Failed to generate CSV: {}", e),
                    }
                }
            }
        }

        // Close PCAP writer on shutdown
        if let Some(ref writer) = pcap_writer {
            writer.close();
            tracing::info!("PCAP writer closed");
        }

        for handle in handles {
            handle.abort();
        }

        Ok(())
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    fn init_tls_ca(&self) -> crate::Result<Option<Arc<nettrap_tls_mitm::CertificateAuthority>>> {
        let needs_tls = self.config.listeners.iter().any(|l| l.use_ssl);
        if !needs_tls {
            return Ok(None);
        }

        // Priority 1: Explicit CA cert/key from config
        if let (Some(cert), Some(key)) = (&self.config.tls_ca_cert, &self.config.tls_ca_key) {
            tracing::info!("Loading TLS CA from config files");
            let ca = nettrap_tls_mitm::CertificateAuthority::from_pem_files(
                std::path::Path::new(cert),
                std::path::Path::new(key),
            ).map_err(|e| crate::Error::Other(format!("Failed to load CA: {}", e)))?;

            if let Some(ref dir) = self.config.tls_cert_dir {
                let _ = ca.save_to_dir(std::path::Path::new(dir));
            }
            return Ok(Some(Arc::new(ca)));
        }

        // Priority 2: mkcert (trusted CA)
        if crate::mkcert::is_mkcert_installed() {
            if let Ok((ca_cert_path, ca_key_path)) = crate::mkcert::get_ca_paths() {
                tracing::info!("Using mkcert trusted CA from {}", ca_cert_path.display());
                match nettrap_tls_mitm::CertificateAuthority::from_pem_files(&ca_cert_path, &ca_key_path) {
                    Ok(mut ca) => {
                        if let Some(ref dir) = self.config.tls_cert_dir {
                            ca = ca.with_cert_dir(dir);
                        }
                        tracing::info!("TLS MITM using mkcert trusted CA — SSL inspection active");
                        return Ok(Some(Arc::new(ca)));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load mkcert CA ({}), falling back to self-signed", e);
                    }
                }
            } else {
                tracing::info!("mkcert found but CA not installed. Run 'nettrap tls install' for trusted certs.");
            }
        }

        // Priority 3: Self-signed CA (untrusted fallback)
        tracing::info!("Generating self-signed TLS CA (untrusted — install mkcert for SSL inspection)");
        let ca = nettrap_tls_mitm::CertificateAuthority::generate()
            .map_err(|e| crate::Error::Other(format!("Failed to generate CA: {}", e)))?;

        if let Some(ref dir) = self.config.tls_cert_dir {
            let _ = ca.save_to_dir(std::path::Path::new(dir));
        }

        Ok(Some(Arc::new(ca)))
    }

    fn spawn_interceptor_task(&self) -> crate::Result<Option<JoinHandle<crate::Result<()>>>> {
        #[cfg(target_os = "windows")]
        {
            use nettrap_interceptor::{Interceptor, InterceptorBuilder};

            let mut builder = InterceptorBuilder::new().buffer_size(65535).promiscuous(true);

            if let Some(interface) = &self._interface {
                builder = builder.interface(interface.clone());
            }

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            let mut interceptor = builder
                .mode(nettrap_core::InterceptionMode::WinDivert)
                .build()
                .map_err(|e| crate::Error::Other(format!("Failed to build WinDivert interceptor: {}", e)))?;

            #[cfg(target_arch = "aarch64")]
            let mut interceptor = builder
                .mode(nettrap_core::InterceptionMode::Userspace)
                .build()
                .map_err(|e| crate::Error::Other(format!("Failed to build Npcap interceptor: {}", e)))?;

            let output_path = self
                .output_override
                .clone()
                .or_else(|| self.config.output_path.clone().map(PathBuf::from));

            return Ok(Some(tokio::spawn(async move {
                interceptor
                    .init()
                    .await
                    .map_err(|e| crate::Error::Other(format!("Failed to initialize interceptor: {}", e)))?;

                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                tracing::info!("WinDivert capture active");

                #[cfg(target_arch = "aarch64")]
                tracing::info!("Npcap capture active");

                loop {
                    match interceptor.recv_packet().await {
                        Ok(packet) => {
                            log_intercepted_packet(&packet, output_path.as_deref()).await?;
                        }
                        Err(nettrap_core::Error::Shutdown) => break,
                        Err(e) => {
                            tracing::warn!("Interceptor receive error: {}", e);
                        }
                    }
                }

                interceptor
                    .shutdown()
                    .await
                    .map_err(|e| crate::Error::Other(format!("Failed to shutdown interceptor: {}", e)))?;
                Ok(())
            })));
        }

        #[cfg(target_os = "linux")]
        {
            use nettrap_interceptor::Interceptor;

            // Collect listener ports for iptables rules
            let mut listener_ports: Vec<(u16, bool)> = self.config.listeners.iter()
                .filter(|l| l.enabled && !l.hidden)
                .map(|l| (l.port, l.protocol == nettrap_core::prelude::Protocol::Tcp))
                .collect();

            if self.config.redirect_all_traffic {
                // Add common ports when redirect_all_traffic is enabled
                let common_tcp_ports: Vec<u16> = vec![
                    20, 21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995,
                    1080, 3128, 3389, 5900, 8000, 8080, 8443, 8888, 6667, 6697,
                ];
                let common_udp_ports: Vec<u16> = vec![53, 67, 68, 69, 123, 161, 162, 514, 1900, 5353];

                let existing_tcp: std::collections::HashSet<u16> = listener_ports.iter()
                    .filter(|(_, is_tcp)| *is_tcp)
                    .map(|(p, _)| *p)
                    .collect();
                let existing_udp: std::collections::HashSet<u16> = listener_ports.iter()
                    .filter(|(_, is_tcp)| !*is_tcp)
                    .map(|(p, _)| *p)
                    .collect();

                for port in common_tcp_ports {
                    if !existing_tcp.contains(&port) {
                        listener_ports.push((port, true));
                    }
                }
                for port in common_udp_ports {
                    if !existing_udp.contains(&port) {
                        listener_ports.push((port, false));
                    }
                }
                tracing::info!("redirect_all_traffic: expanded to {} iptables rules", listener_ports.len());
            }

            let mode = match self.config.effective_network_mode() {
                crate::config::NetworkMode::MultiHost => {
                    nettrap_interceptor::nfqueue::NetworkMode::MultiHost
                }
                _ => nettrap_interceptor::nfqueue::NetworkMode::SingleHost,
            };

            let mut interceptor = nettrap_interceptor::nfqueue::NfqueueInterceptor::new(
                nettrap_interceptor::InterceptorConfig::default()
            )?;
            let flush_on_start = self.config.has_debug_flag("FLUSH_IPTABLES");
            interceptor = interceptor
                .with_mode(mode)
                .with_listener_ports(listener_ports)
                .with_flush_on_start(flush_on_start);

            if let Some(ref iface) = self.config.restrict_interface {
                interceptor = interceptor.with_interface(iface.clone());
            }

            return Ok(Some(tokio::spawn(async move {
                interceptor.init().await
                    .map_err(|e| crate::Error::Other(format!("NFQUEUE init failed: {}", e)))?;

                tracing::info!("NFQUEUE interceptor active");

                // Wait for shutdown signal
                match interceptor.recv_packet().await {
                    Err(nettrap_core::Error::Shutdown) => {}
                    Err(e) => tracing::warn!("NFQUEUE error: {}", e),
                    _ => {}
                }

                interceptor.shutdown().await
                    .map_err(|e| crate::Error::Other(format!("NFQUEUE shutdown failed: {}", e)))?;
                Ok(())
            })));
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            tracing::warn!("`--intercept` requires Windows (WinDivert) or Linux (NFQUEUE)");
            Ok(None)
        }
    }
}

async fn watch_stop_flag(path: Option<std::path::PathBuf>) {
    match path {
        Some(p) => {
            loop {
                if p.exists() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        None => {
            // Never resolves - just wait forever
            std::future::pending::<()>().await;
        }
    }
}

/// Context passed to each listener task with all its configuration and runtime state.
///
/// This struct is created for each listener and passed to the TCP/UDP handler functions.
/// It contains:
/// - Per-listener configuration (name, port, banners, timeouts)
/// - Security settings (host/process filters)
/// - Runtime resources (router, session tracker, NBI collector)
///
/// # Future Refactoring
///
/// This struct has grown large (~40 fields). Consider refactoring into:
/// - `ListenerConfig`: immutable configuration from config file
/// - `ListenerRuntime`: shared runtime resources (router, session tracker, etc.)
/// - `ListenerSecurity`: host/process filtering rules
///
/// See `listener_config.rs` and `listener_runtime.rs` for the separated structures.
#[derive(Clone)]
#[allow(dead_code)]
struct ListenerContext {
    /// Listener name from config (e.g., "dns", "http")
    name: String,
    /// Port number to listen on
    port: u16,
    /// Optional banner string for protocol greeting
    banner: Option<String>,
    /// Directory for HTTP file serving
    webroot: Option<String>,
    /// Directory for FTP file serving
    ftproot: Option<String>,
    /// Directory for TFTP file serving
    tftproot: Option<String>,
    /// Command to execute on new connection
    execute_cmd: Option<String>,
    /// Whether to use TLS/SSL
    use_ssl: bool,
    /// Whether to dump HTTP POST bodies to files
    dump_http_posts: bool,
    /// Prefix for dumped HTTP POST files
    dump_prefix: Option<String>,
    /// Connection timeout in milliseconds
    timeout_ms: u64,
    /// Whether to log hex dump of received data
    log_hexdump: bool,
    /// Process name whitelist/blacklist filter
    process_filter: crate::process_filter::ProcessFilter,
    /// Allowed hosts (empty = all allowed)
    host_whitelist: Vec<String>,
    /// Blocked hosts
    host_blacklist: Vec<String>,
    /// TLS certificate authority for MITM
    ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    /// Protocol router for taste detection
    router: Arc<nettrap_proxy::ProtocolRouter>,
    /// Attribution engine for process attribution
    attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    /// PCAP writer for packet capture
    pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    /// Artificial response delay in milliseconds
    response_delay_ms: u64,
    /// Custom protocol response template
    custom_response: Option<String>,
    /// NBI collector for behavioral indicators
    nbi_collector: Arc<crate::nbi::NbiCollector>,
    /// Session tracker for connection state
    session_tracker: Arc<crate::session::SessionTracker>,
    /// Parsed custom response configuration
    custom_response_config: Option<crate::custom_response::CustomResponseConfig>,
    /// HTTP server version string (e.g., "Apache/2.4.41")
    server_version: Option<String>,
    /// DNS response mode: "auto", "hostname", or "static"
    dns_response_mode: Option<String>,
    /// DNS response IP override
    dns_response_ip: Option<String>,
    /// DNS MX record response
    dns_response_mx: Option<String>,
    /// DNS TXT record response
    dns_response_txt: Option<String>,
    /// Number of NXDOMAIN responses before returning real IP
    dns_nxdomains: Option<u32>,
    /// FTP PASV port range (e.g., "50000-51000")
    pasv_ports: Option<String>,
    /// Rate-limited connection logging deduplication
    connection_dedup: Arc<ConnectionDedup>,
    /// Port forwarding table for dynamic redirects
    port_forward_table: Arc<crate::session::PortForwardTable>,
    /// Maximum concurrent connections (throttling)
    max_connections: Option<u32>,
    /// Banner delay in milliseconds
    banner_delay_ms: u64,
    /// SMTP email storage directory
    smtp_dir: Option<PathBuf>,
}

impl ListenerContext {
    fn is_host_allowed(&self, host: &str) -> bool {
        // Always allow loopback
        if host == "127.0.0.1" || host == "::1" || host.starts_with("127.") {
            return true;
        }
        if !self.host_whitelist.is_empty() {
            return self.host_whitelist.iter().any(|h| h == host);
        }
        if !self.host_blacklist.is_empty() {
            return !self.host_blacklist.iter().any(|h| h == host);
        }
        true
    }

    /// Check if a process name is allowed by global + per-listener filters
    fn is_process_allowed(&self, process_name: &str) -> bool {
        self.process_filter.is_process_allowed(process_name)
    }

    fn fire_execute_cmd(&self, peer: &std::net::SocketAddr) {
        if let Some(ref cmd) = self.execute_cmd {
            crate::execute::execute_on_connect(
                cmd,
                None,
                None,
                &peer.ip().to_string(),
                peer.port(),
                "0.0.0.0",
                self.port,
                &self.name,
            );
        }
    }

    /// Write a PCAP event for captured data (change #5)
    fn write_pcap_event(&self, data: &[u8], peer: &std::net::SocketAddr) {
        if let Some(ref writer) = self.pcap_writer {
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    peer.ip(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    peer.port(),
                    self.port,
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
        }
    }

    /// Write a PCAP event for UDP captured data
    fn write_pcap_event_udp(&self, data: &[u8], peer: &std::net::SocketAddr) {
        if let Some(ref writer) = self.pcap_writer {
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    peer.ip(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    peer.port(),
                    self.port,
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
        }
    }

    /// Write a PCAP event for outbound response data
    fn write_pcap_response(&self, data: &[u8], peer: &std::net::SocketAddr) {
        if let Some(ref writer) = self.pcap_writer {
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    peer.ip(),
                    self.port,
                    peer.port(),
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
        }
    }

    /// Write a PCAP event for outbound UDP response data
    fn write_pcap_response_udp(&self, data: &[u8], peer: &std::net::SocketAddr) {
        if let Some(ref writer) = self.pcap_writer {
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    peer.ip(),
                    self.port,
                    peer.port(),
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
        }
    }

    /// Apply configured response delay before sending data (change #3)
    async fn apply_response_delay(&self) {
        if self.response_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.response_delay_ms)).await;
        }
    }
}

// ─── Interceptor packet logging ──────────────────────────────────────────────

#[allow(dead_code)]
async fn log_intercepted_packet(
    packet: &nettrap_core::Packet,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    tracing::info!(
        "captured {} {}:{} -> {}:{} bytes={}",
        packet.five_tuple.protocol,
        packet.five_tuple.src_ip,
        packet.five_tuple.src_port,
        packet.five_tuple.dst_ip,
        packet.five_tuple.dst_port,
        packet.length
    );

    if let Some(path) = output_path {
        let line = serde_json::json!({
            "timestamp": packet.timestamp,
            "direction": format!("{:?}", packet.direction),
            "protocol": format!("{}", packet.five_tuple.protocol),
            "src_ip": packet.five_tuple.src_ip,
            "src_port": packet.five_tuple.src_port,
            "dst_ip": packet.five_tuple.dst_ip,
            "dst_port": packet.five_tuple.dst_port,
            "length": packet.length,
        });

        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        file.write_all(line.to_string().as_bytes()).await?;
        file.write_all(b"\n").await?;
    }

    Ok(())
}

// ─── UDP Listener (DNS, TFTP) ────────────────────────────────────────────────

async fn run_udp_listener(
    ctx: ListenerContext,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    use nettrap_proto_dns::handler::DnsHandlerTrait;
    use nettrap_proto_tftp::TftpHandlerTrait;
    use tokio::net::UdpSocket;

    let addr = std::net::SocketAddr::new(bind_addr, ctx.port);
    let socket = UdpSocket::bind(addr).await?;

    tracing::info!("UDP listener '{}' listening on {}", ctx.name, addr);

    let mut dns_handler = nettrap_proto_dns::handler::DnsHandler::new();

    // ── Wire DNS response mode ───────────────────────────────────────
    match ctx.dns_response_mode.as_deref() {
        Some("auto") => {
            dns_handler = dns_handler.with_auto_response_ip();
        }
        Some("hostname") => {
            // Resolve hostname's IP as the response
            if let Ok(hostname) = hostname::get() {
                let hostname_str = hostname.to_string_lossy().to_string();
                if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(hostname_str.as_str(), 0)) {
                    for addr in addrs {
                        if !addr.ip().is_loopback() {
                            dns_handler = dns_handler.with_default_response_ip(addr.ip().to_string());
                            break;
                        }
                    }
                }
            }
        }
        _ => {} // "static" or None - use configured IP
    }

    // ── Wire DNS per-listener config ─────────────────────────────────
    if let Some(ref ip) = ctx.dns_response_ip {
        dns_handler = dns_handler.with_default_response_ip(ip);
    }
    if let Some(ref mx) = ctx.dns_response_mx {
        dns_handler = dns_handler.with_default_response_mx(mx);
    }
    if let Some(ref txt) = ctx.dns_response_txt {
        dns_handler = dns_handler.with_default_response_txt(txt);
    }
    if let Some(n) = ctx.dns_nxdomains {
        dns_handler = dns_handler.with_nxdomains(n);
    }

    // ── Wire DNS custom responses from config (change #6) ────────────
    if let Some(ref custom) = ctx.custom_response {
        for entry in custom.split(';') {
            if let Some((domain, ips)) = entry.split_once('=') {
                let ip_list: Vec<String> = ips.split(',').map(|s| s.trim().to_string()).collect();
                dns_handler.add_custom_response(domain.trim(), ip_list);
            }
        }
    }

    let tftp_handler = if let Some(ref root) = ctx.tftproot {
        nettrap_proto_tftp::TftpHandler::new().with_root_dir(root)
    } else {
        nettrap_proto_tftp::TftpHandler::new()
    };

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                if !ctx.is_host_allowed(&src.ip().to_string()) {
                    tracing::debug!("Host {} blocked by filter on {}", src.ip(), ctx.name);
                    continue;
                }

                // Register UDP session
                ctx.session_tracker.register(&src, ctx.port, &ctx.name, "UDP");

                tracing::debug!("UDP '{}' received {} bytes from {}", ctx.name, len, src);

                if ctx.log_hexdump {
                    tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(&buf[..len], 256));
                }

                let query_data = buf[..len].to_vec();

                // Write PCAP event for incoming UDP data
                ctx.write_pcap_event_udp(&query_data, &src);

                if ctx.name == "tftp" || ctx.name.starts_with("tftp") {
                    // TFTP handling
                    if let Some(packet) = nettrap_proto_tftp::TftpPacket::parse(&query_data) {
                        log_event(output_path, &ctx.name, &src, "tftp_request", &format!("{:?}", packet)).await;
                        let nbi = crate::nbi::tftp_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, &format!("{:?}", packet), "");
                        ctx.nbi_collector.record(&nbi).await;
                        match tftp_handler.handle_packet(&packet).await {
                            Ok(responses) => {
                                ctx.apply_response_delay().await;
                                for resp in responses {
                                    let resp_bytes = resp.to_bytes();
                                    ctx.write_pcap_response_udp(&resp_bytes, &src);
                                    if let Err(e) = socket.send_to(&resp_bytes, src).await {
                                        tracing::warn!("Failed to send TFTP response to {}: {}", src, e);
                                    }
                                }
                            }
                            Err(e) => tracing::warn!("TFTP handler error: {}", e),
                        }
                    }
                } else if ctx.name == "dns" || ctx.name.starts_with("dns") {
                    // DNS handling (named DNS listener)
                    match dns_handler.handle_query(&query_data, src).await {
                        Ok(response) => {
                            ctx.apply_response_delay().await;
                            ctx.write_pcap_response_udp(&response, &src);
                            if let Err(e) = socket.send_to(&response, src).await {
                                tracing::warn!("Failed to send UDP response to {}: {}", src, e);
                            }
                            ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                            log_event(output_path, &ctx.name, &src, "dns_query", &format!("{} bytes", len)).await;
                            let nbi = crate::nbi::dns_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, "", "query");
                            ctx.nbi_collector.record(&nbi).await;
                        }
                        Err(e) => {
                            tracing::warn!("UDP handler error from {}: {}", src, e);
                        }
                    }
                } else {
                    // ── Auto-detect UDP protocol via taste router (change #2) ─
                    let detected = ctx.router.route(&query_data, ctx.port);
                    match detected {
                        Some((ref name, score)) if score >= 50 => {
                            tracing::debug!("taste() detected {} (score={}) from {} on UDP", name, score, src);
                            match name.as_str() {
                                "dns" => {
                                    match dns_handler.handle_query(&query_data, src).await {
                                        Ok(response) => {
                                            ctx.apply_response_delay().await;
                                            ctx.write_pcap_response_udp(&response, &src);
                                            if let Err(e) = socket.send_to(&response, src).await {
                                                tracing::warn!("Failed to send DNS response to {}: {}", src, e);
                                            }
                                            log_event(output_path, &ctx.name, &src, "dns_query", &format!("{} bytes", len)).await;
                                            let nbi = crate::nbi::dns_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, "", "query");
                                            ctx.nbi_collector.record(&nbi).await;
                                        }
                                        Err(e) => tracing::warn!("DNS handler error from {}: {}", src, e),
                                    }
                                }
                                "tftp" => {
                                    if let Some(packet) = nettrap_proto_tftp::TftpPacket::parse(&query_data) {
                                        log_event(output_path, &ctx.name, &src, "tftp_request", &format!("{:?}", packet)).await;
                                        let nbi = crate::nbi::tftp_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, &format!("{:?}", packet), "");
                                        ctx.nbi_collector.record(&nbi).await;
                                        match tftp_handler.handle_packet(&packet).await {
                                            Ok(responses) => {
                                                ctx.apply_response_delay().await;
                                                for resp in responses {
                                                    let resp_bytes = resp.to_bytes();
                                                    ctx.write_pcap_response_udp(&resp_bytes, &src);
                                                    if let Err(e) = socket.send_to(&resp_bytes, src).await {
                                                        tracing::warn!("Failed to send TFTP response to {}: {}", src, e);
                                                    }
                                                }
                                            }
                                            Err(e) => tracing::warn!("TFTP handler error: {}", e),
                                        }
                                    }
                                }
                                "snmp" => {
                                    let handler = nettrap_proto_snmp::SnmpHandler::new();
                                    let response = handler.handle(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "snmp_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "snmp");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                "sip" => {
                                    let handler = nettrap_proto_sip::SipHandler::new();
                                    let response = handler.handle(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "sip_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "sip");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                "upnp" => {
                                    let handler = nettrap_proto_upnp::UpnpHandler::new();
                                    let response = handler.handle(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "upnp_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "upnp");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                "ntp" => {
                                    let handler = nettrap_proto_ntp::NtpHandler::new();
                                    let response = handler.handle(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "ntp_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "ntp");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                "coap" => {
                                    let handler = nettrap_proto_coap::CoapHandler::new();
                                    let response = handler.handle(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "coap_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "coap");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                "mqtt" => {
                                    let handler = nettrap_proto_mqtt::MqttHandler::new();
                                    let response = handler.handle_packet(&query_data);
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(&response, &src);
                                    let _ = socket.send_to(&response, src).await;
                                    ctx.session_tracker.update_bytes(&src, "UDP", len as u64, response.len() as u64);
                                    log_event(output_path, &ctx.name, &src, "mqtt_request", &format!("{} bytes", len)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "mqtt");
                                    ctx.nbi_collector.record(&nbi).await;
                                }
                                _ => {
                                    log_event(output_path, &ctx.name, &src, "udp_unknown", &format!("{} bytes, detected={}", len, name)).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    ctx.apply_response_delay().await;
                                    ctx.write_pcap_response_udp(b"OK\n", &src);
                                    let _ = socket.send_to(b"OK\n", src).await;
                                }
                            }
                        }
                        _ => {
                            // Fallback: log unclassified UDP and echo back a short ack
                            tracing::debug!("UDP '{}' unclassified {} bytes from {} (no protocol match)", ctx.name, len, src);
                            log_event(output_path, &ctx.name, &src, "udp_unclassified", &format!("{} bytes", len)).await;
                            let nbi = crate::nbi::raw_nbi(&ctx.name, &src.ip().to_string(), src.port(), ctx.port, len, "unknown");
                            ctx.nbi_collector.record(&nbi).await;
                            ctx.session_tracker.update_bytes(&src, "UDP", len as u64, 0);
                        }
                    }
                }

                ctx.fire_execute_cmd(&src);
            }
            Err(e) => {
                tracing::warn!("UDP recv_from error: {}", e);
            }
        }
    }
}

// ─── TCP Listener (HTTP, HTTPS, SMTP, FTP, POP3, IRC, Raw) ──────────────────

async fn run_tcp_listener(
    ctx: Arc<ListenerContext>,
    bind_addr: std::net::IpAddr,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    use tokio::net::TcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};

    let addr = std::net::SocketAddr::new(bind_addr, ctx.port);
    let listener = TcpListener::bind(addr).await?;
    let active_connections = Arc::new(AtomicU32::new(0));

    tracing::info!("TCP listener '{}' listening on {}", ctx.name, addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Throttle: reject if max_connections exceeded
                if let Some(max) = ctx.max_connections {
                    let current = active_connections.load(Ordering::Relaxed);
                    if current >= max {
                        tracing::warn!("TCP '{}' max connections ({}) reached, rejecting {}", ctx.name, max, peer);
                        drop(stream);
                        continue;
                    }
                }

                // Increment connection counter early to prevent race condition.
                // If we reject the connection later, we decrement before continue.
                // Use AcqRel ordering for proper cross-thread synchronization.
                let conn_counter = Arc::clone(&active_connections);
                conn_counter.fetch_add(1, Ordering::AcqRel);

                if !ctx.is_host_allowed(&peer.ip().to_string()) {
                    tracing::debug!("Host {} blocked by filter on {}", peer.ip(), ctx.name);
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }

                tracing::debug!("TCP '{}' accepted connection from {}", ctx.name, peer);

                // ── Wire attribution + process filtering (with timeout to avoid blocking accept) ─────
                let process_allowed = if let Some(ref attr_engine) = ctx.attribution {
                    let five_tuple = nettrap_core::prelude::FiveTuple::new(
                        peer.ip(),
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        peer.port(),
                        ctx.port,
                        nettrap_core::prelude::Protocol::Tcp,
                    );
                    // Attribution with timeout to prevent accept loop blocking
                    match tokio::task::spawn_blocking({
                        let attr_engine = Arc::clone(attr_engine);
                        move || attr_engine.attribute_flow(&five_tuple)
                    }).await {
                        Ok(attr) if attr.confidence != nettrap_core::prelude::AttributionConfidence::None => {
                            let proc_name = &attr.process.name;
                            tracing::debug!(
                                "Attribution: {} -> {} (pid={})",
                                peer,
                                proc_name,
                                attr.process.pid,
                            );
                            // Register process in session tracker
                            ctx.session_tracker.set_process(&peer, "TCP", Some(proc_name.to_string()), Some(attr.process.pid));
                            ctx.is_process_allowed(proc_name)
                        }
                        Ok(_) => true, // No attribution, allow connection
                        Err(e) => {
                            tracing::warn!("Attribution timeout/error for {}: {}", peer, e);
                            true // Allow connection on attribution error
                        }
                    }
                } else {
                    true
                };

                if !process_allowed {
                    tracing::debug!("Process blocked by filter on {}", ctx.name);
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }

                // Register TCP session
                ctx.session_tracker.register(&peer, ctx.port, &ctx.name, "TCP");

                let ctx_clone = Arc::clone(&ctx);
                let out = output_path.map(|p| p.to_path_buf());
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(ctx_clone, stream, peer, out.as_deref()).await {
                        tracing::debug!("TCP connection error from {}: {}", peer, e);
                    }
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(e) => {
                tracing::warn!("TCP accept error: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(
    ctx: Arc<ListenerContext>,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    use nettrap_proto_pop3::Pop3HandlerTrait;
    use nettrap_proto_irc::IrcHandlerTrait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Rate-limited connection logging - deduplicate connect events
    let dedup_key = format!("{}:{}", ctx.name, peer.ip());
    if ctx.connection_dedup.should_log(&dedup_key) {
        log_event(output_path, &ctx.name, &peer, "connect", "").await;
    }
    ctx.fire_execute_cmd(&peer);

    // Build protocol handlers with config
    let smtp_handler = if let Some(ref b) = ctx.banner {
        let resolved = resolve_service_name(b);
        nettrap_proto_smtp::SmtpHandler::new().with_domain(resolved)
    } else {
        nettrap_proto_smtp::SmtpHandler::new()
    };

    let mut ftp_handler = if let Some(ref b) = ctx.banner {
        nettrap_proto_ftp::FtpHandler::new().with_banner(nettrap_proto_ftp::resolve_banner(b))
    } else {
        nettrap_proto_ftp::FtpHandler::new()
    };
    if let Some(ref root) = ctx.ftproot {
        ftp_handler = ftp_handler.with_root_dir(root);
    }
    if let Some(ref pasv) = ctx.pasv_ports {
        if let Some((start_s, end_s)) = pasv.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
                ftp_handler = ftp_handler.with_pasv_ports(lo, hi);
            }
        }
    }

    let pop3_handler = if let Some(ref b) = ctx.banner {
        let resolved = resolve_service_name(b);
        nettrap_proto_pop3::Pop3Handler::new().with_domain(resolved)
    } else {
        nettrap_proto_pop3::Pop3Handler::new()
    };

    let irc_handler = if let Some(ref b) = ctx.banner {
        let resolved = resolve_service_name(b);
        nettrap_proto_irc::IrcHandler::new().with_server_name(resolved)
    } else {
        nettrap_proto_irc::IrcHandler::new()
    };

    let webroot_server = ctx.webroot.as_ref().map(|w| crate::webroot::WebrootServer::new(w));

    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut irc_nick = "unknown".to_string();

    // Protocol-specific banners (sent immediately on connect)
    let name = ctx.name.as_str();
    if name == "smtp" || name.starts_with("smtp") {
        stream
            .write_all(smtp_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    } else if name == "ftp" || name.starts_with("ftp") {
        stream.write_all(ftp_handler.get_banner()).await?;
        stream.flush().await?;
    } else if name == "pop3" || name.starts_with("pop3") {
        stream
            .write_all(pop3_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    } else if name == "irc" || name.starts_with("irc") {
        stream
            .write_all(irc_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    } else if name == "telnet" || name.starts_with("telnet") {
        let handler = nettrap_proto_telnet::TelnetHandler::new();
        stream.write_all(&handler.get_login_banner()).await?;
        stream.flush().await?;
    } else if name == "ssh" || name.starts_with("ssh") {
        let handler = nettrap_proto_ssh::SshHandler::new();
        stream.write_all(&handler.get_banner()).await?;
        stream.flush().await?;
    } else if name == "mysql" || name.starts_with("mysql") {
        let handler = nettrap_proto_mysql::MysqlHandler::new();
        stream.write_all(&handler.get_handshake()).await?;
        stream.flush().await?;
    }

    // Apply banner delay AFTER banner was sent (delays command processing, not banner delivery)
    if ctx.banner_delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms)).await;
    }

    // If SSL is enabled and we have a CA, try to wrap with TLS
    if ctx.use_ssl {
        if let Some(ref ca) = ctx.ca {
            let wrapper = nettrap_tls_mitm::TlsWrapper::new(Arc::clone(ca));
            // Peek first bytes to detect TLS (512 bytes to capture full ClientHello)
            let mut peek_buf = vec![0u8; 512];
            match stream.peek(&mut peek_buf).await {
                Ok(n) if n >= 3 && peek_buf[0] == 0x16 => {
                    // Compute JA3/JA4 from peeked ClientHello data
                    if let Some((ja3_str, ja3_hash)) = nettrap_proto_tls::ja3::ja3_from_handshake(&peek_buf[..n]) {
                        tracing::info!("JA3: {} ({})", ja3_hash, ja3_str);
                        let mut nbi = crate::nbi::tls_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, "");
                        nbi.add("ja3", ja3_str);
                        nbi.add("ja3_hash", ja3_hash);
                        if let Some(ja4) = nettrap_proto_tls::ja3::ja4_from_handshake(&peek_buf[..n]) {
                            tracing::info!("JA4: {}", ja4);
                            nbi.add("ja4", ja4);
                        }
                        ctx.nbi_collector.record(&nbi).await;
                    }
                    match wrapper.maybe_wrap(stream, &peek_buf[..n]).await {
                        Ok((wrapped, sni)) => {
                            if let Some(ref sni_name) = sni {
                                tracing::debug!("TLS SNI: {} from {}", sni_name, peer);
                                log_event(output_path, &ctx.name, &peer, "tls_sni", sni_name).await;
                                let nbi = crate::nbi::tls_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, sni_name);
                                ctx.nbi_collector.record(&nbi).await;
                            }
                            return handle_wrapped_connection(
                                ctx, wrapped, peer, output_path,
                                &smtp_handler, &ftp_handler, &pop3_handler, &irc_handler,
                                webroot_server.as_ref(),
                            ).await;
                        }
                        Err(e) => {
                            tracing::debug!("TLS wrap failed for {}: {}", peer, e);
                            return Ok(());
                        }
                    }
                }
                _ => {
                    // Not TLS, continue with plain
                }
            }
        }
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("TCP connection closed by {}", peer);
                return Ok(());
            }
            Ok(len) => {
                tracing::debug!("TCP '{}' received {} bytes from {}", ctx.name, len, peer);

                let data = &buf[..len];

                // Update session tracker with received bytes
                ctx.session_tracker.update_bytes(&peer, "TCP", len as u64, 0);

                if ctx.log_hexdump {
                    tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                // Write PCAP event for incoming TCP data
                ctx.write_pcap_event(data, &peer);

                let first_bytes = &data[..len.min(20)];

                let response = if name == "dns" || name.starts_with("dns") {
                    // DNS over TCP: first 2 bytes are length prefix
                    use nettrap_proto_dns::handler::DnsHandlerTrait;
                    let mut tcp_dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
                    // Apply DNS config
                    match ctx.dns_response_mode.as_deref() {
                        Some("auto") => { tcp_dns_handler = tcp_dns_handler.with_auto_response_ip(); }
                        _ => {}
                    }
                    if let Some(ref ip) = ctx.dns_response_ip {
                        tcp_dns_handler = tcp_dns_handler.with_default_response_ip(ip);
                    }
                    if let Some(ref mx) = ctx.dns_response_mx {
                        tcp_dns_handler = tcp_dns_handler.with_default_response_mx(mx);
                    }
                    if let Some(ref txt) = ctx.dns_response_txt {
                        tcp_dns_handler = tcp_dns_handler.with_default_response_txt(txt);
                    }
                    if let Some(n) = ctx.dns_nxdomains {
                        tcp_dns_handler = tcp_dns_handler.with_nxdomains(n);
                    }

                    if data.len() > 2 {
                        let dns_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                        let dns_data = if dns_len > 0 && data.len() >= 2 + dns_len {
                            &data[2..2 + dns_len]
                        } else {
                            &data[2..]
                        };
                        match tcp_dns_handler.handle_query(dns_data, peer).await {
                            Ok(response) => {
                                // Prepend 2-byte length
                                let len_bytes = (response.len() as u16).to_be_bytes();
                                let mut tcp_response = Vec::with_capacity(2 + response.len());
                                tcp_response.extend_from_slice(&len_bytes);
                                tcp_response.extend_from_slice(&response);
                                log_event(output_path, &ctx.name, &peer, "dns_tcp_query", &format!("{} bytes", data.len())).await;
                                let nbi = crate::nbi::dns_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, "", "tcp_query");
                                ctx.nbi_collector.record(&nbi).await;
                                tcp_response
                            }
                            Err(e) => {
                                tracing::warn!("DNS TCP error: {}", e);
                                Vec::new()
                            }
                        }
                    } else {
                        Vec::new()
                    }
                } else if name == "smtp" || name.starts_with("smtp") {
                    let cmd_str = std::str::from_utf8(data).unwrap_or("").trim();
                    let nbi = crate::nbi::smtp_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, cmd_str, "");
                    ctx.nbi_collector.record(&nbi).await;
                    handle_smtp_data(
                        data, &smtp_handler, &mut smtp_data_mode, &mut smtp_data_buf,
                        output_path, &ctx.name, &peer, ctx.smtp_dir.as_deref(),
                    ).await
                } else if name == "ftp" || name.starts_with("ftp") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    tracing::debug!("FTP command from {}: {}", peer, command);
                    log_event(output_path, &ctx.name, &peer, "ftp_command", command).await;
                    let nbi = crate::nbi::ftp_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                    ctx.nbi_collector.record(&nbi).await;
                    ftp_handler.handle(command).to_bytes()
                } else if name == "pop3" || name.starts_with("pop3") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    tracing::debug!("POP3 command from {}: {}", peer, command);
                    log_event(output_path, &ctx.name, &peer, "pop3_command", command).await;
                    let nbi = crate::nbi::pop3_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                    ctx.nbi_collector.record(&nbi).await;
                    match pop3_handler.handle(command).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => b"-ERR Server error\r\n".to_vec(),
                    }
                } else if name == "irc" || name.starts_with("irc") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    // Track NICK changes — sanitize to prevent log injection
                    if command.to_uppercase().starts_with("NICK ") {
                        let raw_nick = command[5..].trim();
                        // Strict sanitization: only alphanumeric, underscore, hyphen
                        // This prevents log injection and XSS while remaining usable
                        irc_nick = raw_nick.chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                            .take(30) // max reasonable nick length
                            .collect();
                        if irc_nick.is_empty() {
                            irc_nick = "unknown".to_string();
                        }
                    }
                    tracing::debug!("IRC command from {} ({}): {}", peer, irc_nick, command);
                    log_event(output_path, &ctx.name, &peer, "irc_command", command).await;
                    let nbi = crate::nbi::irc_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, &irc_nick, command, "");
                    ctx.nbi_collector.record(&nbi).await;
                    match irc_handler.handle(command, &irc_nick).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => Vec::new(),
                    }
                } else if name == "telnet" || name.starts_with("telnet") {
                    let handler = nettrap_proto_telnet::TelnetHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "telnet");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle_command(std::str::from_utf8(data).unwrap_or("")).to_vec()
                } else if name == "ssh" || name.starts_with("ssh") {
                    let handler = nettrap_proto_ssh::SshHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "ssh");
                    ctx.nbi_collector.record(&nbi).await;
                    let mut resp = handler.build_kexinit();
                    resp.extend_from_slice(&handler.build_auth_failure());
                    resp
                } else if name == "smb" || name.starts_with("smb") {
                    let handler = nettrap_proto_smb::SmbHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "smb");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "rdp" || name.starts_with("rdp") {
                    let handler = nettrap_proto_rdp::RdpHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "rdp");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "redis" || name.starts_with("redis") {
                    let mut handler = nettrap_proto_redis::RedisHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "redis");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle_command(data)
                } else if name == "mysql" || name.starts_with("mysql") {
                    let handler = nettrap_proto_mysql::MysqlHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "mysql");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "ldap" || name.starts_with("ldap") {
                    let handler = nettrap_proto_ldap::LdapHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "ldap");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "socks" || name.starts_with("socks") {
                    let handler = nettrap_proto_socks::SocksHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "socks");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "memcached" || name.starts_with("memcached") {
                    let handler = nettrap_proto_memcached::MemcachedHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "memcached");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "nkn" || name.starts_with("nkn") {
                    let handler = nettrap_proto_nkn::NknHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "nkn");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else if name == "postgres" || name.starts_with("postgres") {
                    let handler = nettrap_proto_postgres::PostgresHandler::new();
                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "postgres");
                    ctx.nbi_collector.record(&nbi).await;
                    handler.handle(data)
                } else {
                    // ── Auto-detect protocol via taste router (change #2) ─
                    let detected = ctx.router.route(data, ctx.port);
                    match detected {
                        Some((ref det_name, score)) if score >= 50 => {
                            tracing::debug!("taste() detected {} (score={}) from {}", det_name, score, peer);
                            match det_name.as_str() {
                                "http" => {
                                    tracing::debug!("Detected HTTP protocol from {}", peer);
                                    log_event(output_path, &ctx.name, &peer, "http_request", "").await;

                                    let path = extract_http_path(data);
                                    let host = extract_http_host(data);
                                    let method = extract_http_method(data);
                                    let nbi = crate::nbi::http_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, &method, &path, &host, "", data.len());
                                    ctx.nbi_collector.record(&nbi).await;

                                    // Dump HTTP POST if enabled
                                    if ctx.dump_http_posts && first_bytes.starts_with(b"POST") {
                                        dump_http_post(data, &ctx.dump_prefix, &peer).await;
                                    }

                                    // DynDNS checkip emulation
                                    if host.contains("checkip.dyndns") || host.contains("checkip") {
                                        let src_ip = peer.ip().to_string();
                                        let body = format!("Current IP Address: {}", src_ip);
                                        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                                        tracing::info!("DynDNS checkip response for {}", src_ip);
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: DynDNS-CheckIP/1.0\r\n\r\n{}",
                                            body.len(), date, body
                                        ).into_bytes()
                                    }
                                    // WPAD / proxy.pac
                                    else if path == "/wpad.dat" || path == "/proxy.pac" {
                                        let pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
                                        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                                        tracing::info!("WPAD/PAC response for {}", peer);
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nDate: {}\r\n\r\n{}",
                                            pac.len(), date, pac
                                        ).into_bytes()
                                    }
                                    // Try custom response before webroot, then fake file fallback
                                    else if let Some(ref crc) = ctx.custom_response_config {
                                        if let Some(resp) = crc.build_response(&host, &path) {
                                            resp
                                        } else if let Some(ref ws) = webroot_server {
                                            ws.build_http_response(&path)
                                        } else {
                                            build_http_response_with_fakefile(&path, ctx.server_version.as_deref().unwrap_or("NetTrap"))
                                        }
                                    } else if let Some(ref ws) = webroot_server {
                                        ws.build_http_response(&path)
                                    } else {
                                        build_http_response_with_fakefile(&path, ctx.server_version.as_deref().unwrap_or("NetTrap"))
                                    }
                                }
                                "tls" => {
                                    tracing::debug!("Detected TLS protocol from {}", peer);
                                    let sni = nettrap_tls_mitm::extract_sni(data);
                                    let sni_str = sni.as_deref().unwrap_or("");
                                    let mut nbi = crate::nbi::tls_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, sni_str);
                                    // Compute JA3/JA4 fingerprints
                                    if let Some((ja3_str, ja3_hash)) = nettrap_proto_tls::ja3::ja3_from_handshake(data) {
                                        tracing::info!("TLS JA3: {} (hash: {})", ja3_str, ja3_hash);
                                        nbi.add("ja3", ja3_str);
                                        nbi.add("ja3_hash", ja3_hash);
                                    }
                                    if let Some(ja4) = nettrap_proto_tls::ja3::ja4_from_handshake(data) {
                                        tracing::info!("TLS JA4: {}", ja4);
                                        nbi.add("ja4", ja4);
                                    }
                                    ctx.nbi_collector.record(&nbi).await;
                                    if let Some(ref sni_name) = sni {
                                        log_event(output_path, &ctx.name, &peer, "tls_sni", sni_name).await;
                                    }
                                    log_event(output_path, &ctx.name, &peer, "tls_handshake", "").await;
                                    build_tls_response()
                                }
                                "smtp" => {
                                    // Detected SMTP on a generic listener
                                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                                    tracing::debug!("Detected SMTP from {}: {}", peer, command);
                                    log_event(output_path, &ctx.name, &peer, "smtp_command", command).await;
                                    let nbi = crate::nbi::smtp_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handle_smtp_data(
                                        data, &smtp_handler, &mut smtp_data_mode, &mut smtp_data_buf,
                                        output_path, &ctx.name, &peer, ctx.smtp_dir.as_deref(),
                                    ).await
                                }
                                "ftp" => {
                                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                                    tracing::debug!("Detected FTP from {}: {}", peer, command);
                                    log_event(output_path, &ctx.name, &peer, "ftp_command", command).await;
                                    let nbi = crate::nbi::ftp_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    ftp_handler.handle(command).to_bytes()
                                }
                                "pop3" => {
                                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                                    tracing::debug!("Detected POP3 from {}: {}", peer, command);
                                    log_event(output_path, &ctx.name, &peer, "pop3_command", command).await;
                                    let nbi = crate::nbi::pop3_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    match pop3_handler.handle(command).await {
                                        Ok(resp) => resp.to_bytes(),
                                        Err(_) => b"-ERR Server error\r\n".to_vec(),
                                    }
                                }
                                "irc" => {
                                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                                    if command.to_uppercase().starts_with("NICK ") {
                                        let raw_nick = command[5..].trim();
                                        // Strict sanitization: only alphanumeric, underscore, hyphen
                                        irc_nick = raw_nick.chars()
                                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                                            .take(30)
                                            .collect();
                                        if irc_nick.is_empty() {
                                            irc_nick = "unknown".to_string();
                                        }
                                    }
                                    tracing::debug!("Detected IRC from {} ({}): {}", peer, irc_nick, command);
                                    log_event(output_path, &ctx.name, &peer, "irc_command", command).await;
                                    let nbi = crate::nbi::irc_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, &irc_nick, command, "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    match irc_handler.handle(command, &irc_nick).await {
                                        Ok(resp) => resp.to_bytes(),
                                        Err(_) => Vec::new(),
                                    }
                                }
                                "telnet" => {
                                    let handler = nettrap_proto_telnet::TelnetHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "telnet");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle_command(std::str::from_utf8(data).unwrap_or("")).to_vec()
                                }
                                "ssh" => {
                                    let handler = nettrap_proto_ssh::SshHandler::new();
                                    if let Some(version) = nettrap_proto_ssh::SshHandler::parse_client_version(data) {
                                        tracing::warn!("SSH client version: {}", version);
                                    }
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "ssh");
                                    ctx.nbi_collector.record(&nbi).await;
                                    let mut resp = handler.build_kexinit();
                                    resp.extend_from_slice(&handler.build_auth_failure());
                                    resp
                                }
                                "smb" => {
                                    let handler = nettrap_proto_smb::SmbHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "smb");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "rdp" => {
                                    let handler = nettrap_proto_rdp::RdpHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "rdp");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "redis" => {
                                    let mut handler = nettrap_proto_redis::RedisHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "redis");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle_command(data)
                                }
                                "mysql" => {
                                    let handler = nettrap_proto_mysql::MysqlHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "mysql");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "ldap" => {
                                    let handler = nettrap_proto_ldap::LdapHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "ldap");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "socks" => {
                                    let handler = nettrap_proto_socks::SocksHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "socks");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "memcached" => {
                                    let handler = nettrap_proto_memcached::MemcachedHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "memcached");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "nkn" => {
                                    let handler = nettrap_proto_nkn::NknHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "nkn");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                "postgres" => {
                                    let handler = nettrap_proto_postgres::PostgresHandler::new();
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "postgres");
                                    ctx.nbi_collector.record(&nbi).await;
                                    handler.handle(data)
                                }
                                _ => {
                                    tracing::debug!("taste() matched {} from {} but no specific handler", det_name, peer);
                                    let raw_handler = if let Some(ref custom) = ctx.custom_response {
                                        nettrap_proto_raw::RawHandler::from_custom_response(custom)
                                    } else {
                                        nettrap_proto_raw::RawHandler::new() // echo mode
                                    };
                                    let raw_resp = raw_handler.handle(data);
                                    log_event(output_path, &ctx.name, &peer, "raw", &format!("{} bytes", data.len())).await;
                                    let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, data.len(), "");
                                    ctx.nbi_collector.record(&nbi).await;
                                    raw_resp.to_bytes()
                                }
                            }
                        }
                        _ => {
                            tracing::debug!("Unknown protocol from {}", peer);
                            let raw_handler = if let Some(ref custom) = ctx.custom_response {
                                nettrap_proto_raw::RawHandler::from_custom_response(custom)
                            } else {
                                nettrap_proto_raw::RawHandler::new() // echo mode
                            };
                            let raw_resp = raw_handler.handle(data);
                            log_event(output_path, &ctx.name, &peer, "raw", &format!("{} bytes", len)).await;
                            let nbi = crate::nbi::raw_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, len, "");
                            ctx.nbi_collector.record(&nbi).await;
                            raw_resp.to_bytes()
                        }
                    }
                };

                if !response.is_empty() {
                    // Write outbound PCAP event for response
                    ctx.write_pcap_response(&response, &peer);
                    // ── Wire response_delay_ms (change #3) ───────────────
                    ctx.apply_response_delay().await;
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                }
            }
            Err(e) => {
                tracing::debug!("TCP read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

/// Handle connection that has been wrapped with TLS
async fn handle_wrapped_connection(
    ctx: Arc<ListenerContext>,
    mut stream: nettrap_tls_mitm::WrappedStream,
    peer: std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    _ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> crate::Result<()> {
    use nettrap_proto_pop3::Pop3HandlerTrait;
    use nettrap_proto_irc::IrcHandlerTrait;

    let name = ctx.name.as_str();
    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut irc_nick = "unknown".to_string();

    // Send banner over TLS
    if name == "smtp" || name.starts_with("smtp") {
        stream.write_all(smtp_handler.get_welcome_banner().as_bytes()).await?;
        stream.flush().await?;
    } else if name == "pop3" || name.starts_with("pop3") {
        stream.write_all(pop3_handler.get_welcome_banner().as_bytes()).await?;
        stream.flush().await?;
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(len) => {
                let data = &buf[..len];

                if ctx.log_hexdump {
                    tracing::debug!("TLS Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                // Write PCAP event for incoming TLS data
                ctx.write_pcap_event(data, &peer);

                let response = if name == "smtp" || name.starts_with("smtp") {
                    let cmd_str = std::str::from_utf8(data).unwrap_or("").trim();
                    let nbi = crate::nbi::smtp_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, cmd_str, "");
                    ctx.nbi_collector.record(&nbi).await;
                    handle_smtp_data(
                        data, smtp_handler, &mut smtp_data_mode, &mut smtp_data_buf,
                        output_path, &ctx.name, &peer, ctx.smtp_dir.as_deref(),
                    ).await
                } else if name == "pop3" || name.starts_with("pop3") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    log_event(output_path, &ctx.name, &peer, "pop3_command", command).await;
                    let nbi = crate::nbi::pop3_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, command, "");
                    ctx.nbi_collector.record(&nbi).await;
                    match pop3_handler.handle(command).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => b"-ERR Server error\r\n".to_vec(),
                    }
                } else if name == "irc" || name.starts_with("irc") {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    if command.to_uppercase().starts_with("NICK ") {
                        let raw_nick = command[5..].trim();
                        // Strict sanitization: only alphanumeric, underscore, hyphen
                        irc_nick = raw_nick.chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                            .take(30)
                            .collect();
                        if irc_nick.is_empty() {
                            irc_nick = "unknown".to_string();
                        }
                    }
                    log_event(output_path, &ctx.name, &peer, "irc_command", command).await;
                    let nbi = crate::nbi::irc_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, &irc_nick, command, "");
                    ctx.nbi_collector.record(&nbi).await;
                    match irc_handler.handle(command, &irc_nick).await {
                        Ok(resp) => resp.to_bytes(),
                        Err(_) => Vec::new(),
                    }
                } else {
                    // HTTP over TLS
                    log_event(output_path, &ctx.name, &peer, "https_request", "").await;

                    let path = extract_http_path(data);
                    let host = extract_http_host(data);
                    let method = extract_http_method(data);
                    let nbi = crate::nbi::http_nbi(&ctx.name, &peer.ip().to_string(), peer.port(), ctx.port, &method, &path, &host, "", data.len());
                    ctx.nbi_collector.record(&nbi).await;

                    if ctx.dump_http_posts && data.starts_with(b"POST") {
                        dump_http_post(data, &ctx.dump_prefix, &peer).await;
                    }

                    // DynDNS checkip emulation (HTTPS)
                    if host.contains("checkip.dyndns") || host.contains("checkip") {
                        let src_ip = peer.ip().to_string();
                        let body = format!("Current IP Address: {}", src_ip);
                        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                        tracing::info!("DynDNS checkip response for {} (HTTPS)", src_ip);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: DynDNS-CheckIP/1.0\r\n\r\n{}",
                            body.len(), date, body
                        ).into_bytes()
                    }
                    // WPAD / proxy.pac (HTTPS)
                    else if path == "/wpad.dat" || path == "/proxy.pac" {
                        let pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
                        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                        tracing::info!("WPAD/PAC response for {} (HTTPS)", peer);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nDate: {}\r\n\r\n{}",
                            pac.len(), date, pac
                        ).into_bytes()
                    }
                    // Try custom response before webroot, then fake file fallback
                    else if let Some(ref crc) = ctx.custom_response_config {
                        if let Some(resp) = crc.build_response(&host, &path) {
                            resp
                        } else if let Some(ws) = webroot_server {
                            ws.build_http_response(&path)
                        } else {
                            build_http_response_with_fakefile(&path, ctx.server_version.as_deref().unwrap_or("NetTrap"))
                        }
                    } else if let Some(ws) = webroot_server {
                        ws.build_http_response(&path)
                    } else {
                        build_http_response_with_fakefile(&path, ctx.server_version.as_deref().unwrap_or("NetTrap"))
                    }
                };

                if !response.is_empty() {
                    // Write outbound PCAP event for TLS response
                    ctx.write_pcap_response(&response, &peer);
                    // ── Wire response_delay_ms in TLS handler (change #3)
                    ctx.apply_response_delay().await;
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                }
            }
            Err(e) => {
                tracing::debug!("TLS read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

// ─── SMTP data mode helper ───────────────────────────────────────────────────

async fn handle_smtp_data(
    data: &[u8],
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    output_path: Option<&std::path::Path>,
    listener_name: &str,
    peer: &std::net::SocketAddr,
    smtp_dir: Option<&std::path::Path>,
) -> Vec<u8> {
    use nettrap_proto_smtp::SmtpHandlerTrait;

    const MAX_SMTP_DATA_SIZE: usize = 50 * 1024 * 1024; // 50 MB limit

    if *smtp_data_mode {
        if smtp_data_buf.len() + data.len() > MAX_SMTP_DATA_SIZE {
            tracing::warn!("SMTP DATA buffer exceeded limit from {} ({} bytes), discarding", peer, smtp_data_buf.len() + data.len());
            *smtp_data_mode = false;
            smtp_data_buf.clear();
            return b"552 Message too large\r\n".to_vec();
        }
        smtp_data_buf.extend_from_slice(data);
        let has_terminator = smtp_data_buf.windows(5).any(|w| w == b"\r\n.\r\n")
            || smtp_data_buf.windows(3).any(|w| w == b"\n.\n");
        if has_terminator {
            let body_size = smtp_data_buf.len();
            tracing::debug!("SMTP DATA complete from {}: {} bytes", peer, body_size);
            log_event(output_path, listener_name, peer, "smtp_data", &format!("{} bytes", body_size)).await;

            let mbox_dir = smtp_dir
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("/var/log/nettrap/smtp"));
            let _ = tokio::fs::create_dir_all(&mbox_dir).await;
            let filename = format!("{}/{}.eml", mbox_dir.display(), uuid::Uuid::new_v4());
            let _ = tokio::fs::write(&filename, &*smtp_data_buf).await;
            tracing::info!("SMTP email saved to {}", filename);

            *smtp_data_mode = false;
            smtp_data_buf.clear();
            format!("250 OK Queued as {}\r\n", uuid::Uuid::new_v4()).into_bytes()
        } else {
            Vec::new()
        }
    } else {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("SMTP command from {}: {}", peer, command);
        log_event(output_path, listener_name, peer, "smtp_command", command).await;
        match smtp_handler.handle(command).await {
            Ok(resp) => {
                if resp.code == 354 {
                    *smtp_data_mode = true;
                    smtp_data_buf.clear();
                }
                format!("{} {}\r\n", resp.code, resp.message).into_bytes()
            }
            Err(_) => b"500 Error\r\n".to_vec(),
        }
    }
}

/// Build TLS response (minimal TLS ServerHello)
fn build_tls_response() -> Vec<u8> {
    let mut response = vec![22, 3, 3, 0, 2, 0, 0];
    response.push(0x01);
    response.push(0x00);
    response.extend_from_slice(&[22, 3, 3, 0, 2, 0, 0]);
    response
}
