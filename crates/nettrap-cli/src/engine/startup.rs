use std::path::PathBuf;
use std::sync::Arc;

use nettrap_core::prelude::Protocol;

use crate::config::EngineConfig;
use crate::database::DatabaseBackend;
use crate::listener_context::ListenerContext;
use crate::listener_runtime::{ListenerRuntime, ListenerSecurity};

pub struct StartupContext {
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    pub flow_manager: Arc<nettrap_flow::FlowManager>,
    pub runtime_health: Arc<nettrap_api::RuntimeHealth>,
    pub nbi_collector: Arc<crate::nbi::NbiCollector>,
    pub session_tracker: Arc<crate::session::SessionTracker>,
    pub session_cleanup_task: Option<tokio::task::JoinHandle<()>>,
    pub background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub port_forward_table: Arc<crate::session::PortForwardTable>,
    pub node_identity: Arc<crate::distributed::NodeIdentity>,
    pub run_id: String,
    pub database_node_id: Option<String>,
    pub database: Option<Arc<DatabaseBackend>>,
    pub output_path: Option<PathBuf>,
    pub nbi_path: Option<PathBuf>,
    pub http_post_dump_dir: Option<String>,
    pub log_hexdump: bool,
    pub global_process_whitelist: Vec<String>,
    pub global_process_blacklist: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ValidatedRedirectDefaults {
    tcp: Option<ValidatedDefaultListener>,
    udp: Option<ValidatedDefaultListener>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedDefaultListener {
    name: String,
    port: u16,
}

pub fn create_startup_context(
    config: &EngineConfig,
    output_override: Option<PathBuf>,
) -> crate::Result<StartupContext> {
    let redirect_defaults = validate_redirect_defaults(config)?;
    let ca = init_tls_ca(config)?;
    let router = init_protocol_router(&redirect_defaults);
    let attribution = init_attribution(config);
    let pcap_writer = init_pcap_writer(config)?;

    let output_path = output_override
        .clone()
        .or_else(|| config.output_path.clone().map(PathBuf::from));

    let nbi_path = output_path.as_ref().map(|p| {
        let stem = p.file_stem().unwrap_or_default().to_string_lossy();
        p.with_file_name(format!("{}_nbi.jsonl", stem))
    });
    if let Some(ref nbi_path) = nbi_path {
        validate_nbi_output_path(nbi_path)?;
    }

    let node_identity = Arc::new(crate::distributed::NodeIdentity::generate(
        config.distributed.node_id.clone(),
        config.distributed.node_region.clone(),
        config.distributed.node_tags.clone(),
    ));
    let run_id = uuid::Uuid::new_v4().to_string();

    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
    let nbi_collector = Arc::new(crate::nbi::NbiCollector::new(nbi_path.clone()));
    nbi_collector.attach_runtime_health(Arc::clone(&runtime_health));
    if config.distributed.enabled {
        let fanout = Arc::new(crate::distributed::build_event_fanout(&config.distributed)?);
        fanout.attach_runtime_health(Arc::clone(&runtime_health));
        nbi_collector.attach_fanout(fanout);
    } else {
        runtime_health.set_distributed_export_disabled();
    }
    let session_tracker = Arc::new(crate::session::SessionTracker::new());
    let port_forward_table = Arc::new(crate::session::PortForwardTable::new());
    let session_cleanup_task = if tokio::runtime::Handle::try_current().is_ok() {
        Some(start_runtime_cleanup_task(
            Arc::clone(&session_tracker),
            Arc::clone(&port_forward_table),
            Arc::clone(&flow_manager),
        ))
    } else {
        None
    };
    let listener_protocols = config
        .listeners
        .iter()
        .map(|listener| (listener.name.clone(), listener.protocol))
        .collect();
    nbi_collector.attach_session_tracker(Arc::clone(&session_tracker));
    nbi_collector.attach_listener_protocols(listener_protocols);

    Ok(StartupContext {
        ca,
        router,
        attribution,
        pcap_writer,
        flow_manager,
        runtime_health,
        nbi_collector,
        session_tracker,
        session_cleanup_task,
        background_tasks: Vec::new(),
        port_forward_table,
        node_identity,
        run_id,
        database_node_id: None,
        database: None,
        output_path,
        nbi_path,
        http_post_dump_dir: config.http_post_dump_dir.clone(),
        log_hexdump: config.log_hexdump,
        global_process_whitelist: config.global_process_whitelist.clone(),
        global_process_blacklist: config.global_process_blacklist.clone(),
    })
}

fn validate_nbi_output_path(path: &PathBuf) -> crate::Result<()> {
    if path.is_dir() {
        return Err(crate::Error::Config(format!(
            "NBI output path {} is a directory, expected a writable file",
            path.display()
        )));
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            crate::Error::Config(format!(
                "failed to create NBI output directory {}: {}",
                parent.display(),
                err
            ))
        })?;
    }

    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|err| {
            crate::Error::Config(format!(
                "failed to validate writable NBI output path {}: {}",
                path.display(),
                err
            ))
        })
}

fn validate_redirect_defaults(config: &EngineConfig) -> crate::Result<ValidatedRedirectDefaults> {
    if !config.redirect_all_traffic {
        return Ok(ValidatedRedirectDefaults::default());
    }

    let tcp = validate_redirect_default_listener(
        config,
        config.default_tcp_listener.as_deref(),
        Protocol::Tcp,
    )?;
    let udp = validate_redirect_default_listener(
        config,
        config.default_udp_listener.as_deref(),
        Protocol::Udp,
    )?;

    if tcp.is_none() && udp.is_none() {
        return Err(crate::Error::Config(
            "redirect_all_traffic requires at least one valid default listener".into(),
        ));
    }

    Ok(ValidatedRedirectDefaults { tcp, udp })
}

fn validate_redirect_default_listener(
    config: &EngineConfig,
    listener_name: Option<&str>,
    protocol: Protocol,
) -> crate::Result<Option<ValidatedDefaultListener>> {
    let Some(listener_name) = listener_name else {
        return Ok(None);
    };

    let Some(listener) = find_spawnable_default_listener(config, listener_name, protocol) else {
        return Err(crate::Error::Config(format!(
            "redirect_all_traffic requires a valid {} default listener, but '{}' does not resolve to a spawnable {} listener",
            protocol_label(protocol),
            listener_name,
            protocol_label(protocol),
        )));
    };
    let port = resolve_default_listener_port(config, listener_name, protocol)
        .expect("validated default listener should always resolve to a port");

    Ok(Some(ValidatedDefaultListener {
        name: listener.name.clone(),
        port,
    }))
}

fn find_spawnable_default_listener<'a>(
    config: &'a EngineConfig,
    listener_name: &str,
    protocol: Protocol,
) -> Option<&'a crate::config::ListenerConfig> {
    config.listeners.iter().find(|listener| {
        listener.protocol == protocol
            && listener.name.eq_ignore_ascii_case(listener_name)
            && super::listener_should_spawn(config, listener)
    })
}

pub(super) fn resolve_default_listener_port(
    config: &EngineConfig,
    listener_name: &str,
    protocol: Protocol,
) -> Option<u16> {
    find_spawnable_default_listener(config, listener_name, protocol).map(|listener| listener.port)
}

fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        _ => "unsupported",
    }
}

fn start_runtime_cleanup_task(
    session_tracker: Arc<crate::session::SessionTracker>,
    port_forward_table: Arc<crate::session::PortForwardTable>,
    flow_manager: Arc<nettrap_flow::FlowManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(session_tracker.cleanup_interval()).await;
            let expired_sessions = session_tracker.cleanup_expired_sessions();
            for session in expired_sessions {
                if let Some(five_tuple) = session.to_five_tuple() {
                    flow_manager.remove(&nettrap_core::prelude::FlowKey::from_five_tuple(
                        &five_tuple,
                    ));
                }
            }
            port_forward_table.purge_stale_destinations(session_tracker.ttl());
            tracing::debug!(
                "Session cleanup completed, active sessions: {}",
                session_tracker.active_count()
            );
        }
    })
}

pub async fn with_database(
    mut ctx: StartupContext,
    config: &EngineConfig,
) -> crate::Result<StartupContext> {
    let mut db_config = config.database.clone();
    if db_config.node_id.is_none() {
        db_config.node_id = Some(ctx.node_identity.node_id.clone());
    }

    match crate::database::init_database(&db_config, &ctx.run_id).await {
        Ok(Some(db)) => {
            ctx.database_node_id = db_config.node_id.clone();
            let db = Arc::new(db);
            ctx.nbi_collector.attach_database(Arc::clone(&db));
            ctx.database = Some(db);
        }
        Ok(None) => {}
        Err(err) => {
            return Err(crate::Error::Config(format!(
                "database initialization failed: {}",
                err
            )));
        }
    }

    Ok(ctx)
}

fn init_tls_ca(
    config: &EngineConfig,
) -> crate::Result<Option<Arc<nettrap_tls_mitm::CertificateAuthority>>> {
    let needs_tls = config.listeners.iter().any(|l| l.use_ssl);
    if !needs_tls {
        return Ok(None);
    }

    if let (Some(cert), Some(key)) = (&config.tls_ca_cert, &config.tls_ca_key) {
        tracing::info!("Loading TLS CA from config files");
        let ca = nettrap_tls_mitm::CertificateAuthority::from_pem_files(
            std::path::Path::new(cert),
            std::path::Path::new(key),
        )
        .map_err(|e| crate::Error::Other(format!("Failed to load CA: {}", e)))?;

        if let Some(ref dir) = config.tls_cert_dir {
            if let Err(e) = ca.save_to_dir(std::path::Path::new(dir)) {
                tracing::warn!("Failed to save TLS CA to {}: {}", dir, e);
            }
        }
        return Ok(Some(Arc::new(ca)));
    }

    if crate::mkcert::is_mkcert_installed() {
        if let Ok((ca_cert_path, ca_key_path)) = crate::mkcert::get_ca_paths() {
            tracing::info!("Using mkcert trusted CA from {}", ca_cert_path.display());
            match nettrap_tls_mitm::CertificateAuthority::from_pem_files(
                &ca_cert_path,
                &ca_key_path,
            ) {
                Ok(mut ca) => {
                    if let Some(ref dir) = config.tls_cert_dir {
                        ca = ca.with_cert_dir(dir);
                    }
                    tracing::info!("TLS MITM using mkcert trusted CA — SSL inspection active");
                    return Ok(Some(Arc::new(ca)));
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load mkcert CA ({}), falling back to self-signed",
                        e
                    );
                }
            }
        } else {
            tracing::info!(
                "mkcert found but CA not installed. Run 'nettrap tls install' for trusted certs."
            );
        }
    }

    tracing::info!("Generating self-signed TLS CA (untrusted — install mkcert for SSL inspection)");
    let ca = nettrap_tls_mitm::CertificateAuthority::generate()
        .map_err(|e| crate::Error::Other(format!("Failed to generate CA: {}", e)))?;

    if let Some(ref dir) = config.tls_cert_dir {
        if let Err(e) = ca.save_to_dir(std::path::Path::new(dir)) {
            tracing::warn!("Failed to save CA certificate to {:?}: {}", dir, e);
        }
    }

    Ok(Some(Arc::new(ca)))
}

fn init_protocol_router(
    defaults: &ValidatedRedirectDefaults,
) -> Arc<nettrap_proxy::ProtocolRouter> {
    crate::router_setup::RouterSetup::build(
        defaults.tcp.as_ref().map(|listener| listener.name.clone()),
        defaults.udp.as_ref().map(|listener| listener.name.clone()),
    )
}

fn init_attribution(config: &EngineConfig) -> Option<Arc<nettrap_attribution::AttributionEngine>> {
    if config.attribution_enabled {
        Some(Arc::new(
            nettrap_attribution::AttributionEngine::with_timeout(std::time::Duration::from_millis(
                config.attribution_timeout_ms,
            )),
        ))
    } else {
        None
    }
}

fn init_pcap_writer(config: &EngineConfig) -> crate::Result<Option<Arc<nettrap_pcap::PcapWriter>>> {
    if !config.pcap_enabled {
        return Ok(None);
    }

    let path = config.pcap_path.clone().unwrap_or_else(|| {
        let prefix = config.pcap_prefix.as_deref().unwrap_or("packets");
        format!(
            "{}_{}.pcap",
            prefix,
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        )
    });

    let writer = Arc::new(nettrap_pcap::PcapWriter::new(&path));
    writer
        .open()
        .map_err(|e| crate::Error::Other(format!("PCAP open failed: {}", e)))?;
    tracing::info!("PCAP recording to {}", path);

    Ok(Some(writer))
}

pub fn build_listener_context(
    listener: &crate::config::ListenerConfig,
    startup: &StartupContext,
    smtp_dir_override: Option<std::path::PathBuf>,
) -> ListenerContext {
    let smtp_dir = smtp_dir_override.or_else(|| {
        startup
            .output_path
            .as_ref()
            .map(|p| p.parent().unwrap_or(p).join("smtp"))
    });

    let process_filter = crate::process_filter::ProcessFilter::build(
        startup.global_process_whitelist.clone(),
        startup.global_process_blacklist.clone(),
        listener.process_whitelist.clone(),
        listener.process_blacklist.clone(),
    );

    let security = ListenerSecurity::new(
        process_filter.clone(),
        listener.host_whitelist.clone(),
        listener.host_blacklist.clone(),
    );

    let runtime = ListenerRuntime::new(
        startup.ca.clone(),
        Arc::clone(&startup.router),
        startup.attribution.clone(),
        startup.pcap_writer.clone(),
        Arc::clone(&startup.nbi_collector),
        Arc::clone(&startup.session_tracker),
        Arc::clone(&startup.port_forward_table),
        Arc::clone(&startup.flow_manager),
    );

    ListenerContext::builder()
        .name(listener.name.clone())
        .port(listener.port)
        .banner(listener.banner.clone())
        .webroot(listener.webroot.clone())
        .ftproot(listener.ftproot.clone())
        .tftproot(listener.tftproot.clone())
        .execute_cmd(listener.execute_cmd.clone())
        .use_ssl(listener.use_ssl)
        .dump_http_posts(listener.dump_http_posts)
        .dump_prefix(
            listener
                .dump_http_posts_prefix
                .clone()
                .or_else(|| startup.http_post_dump_dir.clone()),
        )
        .timeout_ms(listener.timeout_ms)
        .response_delay_ms(listener.response_delay_ms)
        .custom_response(listener.custom_response.clone())
        .server_version(listener.server_version.clone())
        .dns_response_mode(listener.dns_response_mode.clone())
        .dns_response_ip(listener.dns_response_ip.clone())
        .dns_response_mx(listener.dns_response_mx.clone())
        .dns_response_txt(listener.dns_response_txt.clone())
        .dns_nxdomains(listener.dns_nxdomains)
        .pasv_ports(listener.pasv_ports.clone())
        .banner_delay_ms(listener.banner_delay_ms)
        .smtp_dir(smtp_dir)
        .log_hexdump(startup.log_hexdump)
        .max_connections(listener.max_connections)
        .process_filter(process_filter)
        .host_whitelist(listener.host_whitelist.clone())
        .host_blacklist(listener.host_blacklist.clone())
        .build(security, runtime)
}

pub fn init_windows_network(config: &EngineConfig) {
    if cfg!(target_os = "windows") {
        if config.has_debug_flag("FIXGATEWAY") {
            crate::windows_setup::fix_gateway();
        }
        if config.has_debug_flag("FIXDNS") {
            crate::windows_setup::fix_dns();
        }
        if config.has_debug_flag("STOPDNSSERVICE") {
            crate::windows_setup::stop_dns_service();
        }
    }
}

pub fn init_windows_ca_trust(config: &EngineConfig) {
    if let Some(ref dir) = config.tls_cert_dir {
        let cert_path = format!("{}/ca.crt", dir);
        if std::path::Path::new(&cert_path).exists() {
            crate::windows_setup::install_ca_trust(&cert_path);
        }
    }
}

pub fn init_distributed(
    config: &EngineConfig,
    node_identity: &Arc<crate::distributed::NodeIdentity>,
    runtime_health: &Arc<nettrap_api::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
    bg_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> crate::Result<()> {
    if !config.distributed.enabled {
        if config.distributed.health_bind.is_some()
            || config.distributed.metrics_bind.is_some()
            || config.distributed.control_plane_url.is_some()
            || !config.distributed.event_sinks.is_empty()
            || config.distributed.heartbeat_interval_secs > 0
        {
            tracing::warn!(
                "Distributed config is present but distributed.enabled=false; health, metrics, heartbeat, and event sinks remain disabled"
            );
        }
        return Ok(());
    }

    tracing::info!(
        "Distributed mode enabled — node_id: {}",
        node_identity.node_id
    );

    if let Some(ref health_bind) = config.distributed.health_bind {
        let (listener, local_addr) = crate::distributed::bind_health_server(health_bind)?;
        tracing::info!("health/readiness server on {}", local_addr);
        let bind = health_bind.clone();
        let node = Arc::clone(node_identity);
        let runtime_health = Arc::clone(runtime_health);
        let fatal_runtime_tx = fatal_runtime_tx.clone();
        bg_tasks.push(tokio::spawn(async move {
            if let Err(err) =
                crate::distributed::serve_health_server(listener, node, runtime_health.clone())
                    .await
            {
                let message = format!("Health/readiness server failed on {}: {}", bind, err);
                runtime_health.set_fatal_error(message.clone());
                let _ = fatal_runtime_tx.send(message.clone());
                tracing::warn!("{}", message);
            }
        }));
    }

    if let Some(ref metrics_bind) = config.distributed.metrics_bind {
        let (listener, local_addr) = crate::distributed::bind_metrics_server(metrics_bind)?;
        tracing::info!("metrics server on {}", local_addr);
        let bind = metrics_bind.clone();
        let node = Arc::clone(node_identity);
        let runtime_health = Arc::clone(runtime_health);
        let fatal_runtime_tx = fatal_runtime_tx.clone();
        bg_tasks.push(tokio::spawn(async move {
            if let Err(err) =
                crate::distributed::serve_metrics_server(listener, node, runtime_health.clone())
                    .await
            {
                let message = format!("Metrics server failed on {}: {}", bind, err);
                runtime_health.set_fatal_error(message.clone());
                let _ = fatal_runtime_tx.send(message.clone());
                tracing::warn!("{}", message);
            }
        }));
    }

    if let Some(ref control_url) = config.distributed.control_plane_url {
        let url = control_url.clone();
        let token = config.distributed.control_plane_token.clone();
        let node = Arc::clone(node_identity);
        let interval = config.distributed.heartbeat_interval_secs;
        if interval > 0 {
            let runtime_health = Arc::clone(runtime_health);
            let fatal_runtime_tx = fatal_runtime_tx.clone();
            bg_tasks.push(tokio::spawn(async move {
                if let Err(err) =
                    crate::distributed::run_heartbeat(url, token, node, interval).await
                {
                    let message = format!("Control plane heartbeat failed: {}", err);
                    runtime_health.set_fatal_error(message.clone());
                    let _ = fatal_runtime_tx.send(message.clone());
                    tracing::warn!("{}", message);
                }
            }));
        }
    }

    Ok(())
}

pub fn init_faketime(config: &EngineConfig, bg_tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    if config.faketime.enabled {
        crate::faketime::set_delta(config.faketime.init_delta);
        tracing::info!(
            "FakeTime mode enabled — initial delta: {} seconds",
            config.faketime.init_delta
        );
        let ft_config = config.faketime.clone();
        bg_tasks.push(tokio::spawn(async move {
            crate::faketime::run_auto_increment(ft_config).await;
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_database_attaches_backend_to_nbi_collector() {
        let mut config = EngineConfig::default();
        let db_path =
            std::env::temp_dir().join(format!("nettrap-startup-test-{}.db", uuid::Uuid::new_v4()));
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(db_path.to_string_lossy().to_string());

        let startup = create_startup_context(&config, None).unwrap();
        let startup = with_database(startup, &config).await.unwrap();

        let db = startup
            .database
            .as_ref()
            .expect("database should be attached")
            .clone();
        let nbi = crate::nbi::raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &crate::session::SessionDestination::unknown(8080),
            4,
            "test",
        );
        startup.nbi_collector.record(&nbi).await;
        startup.nbi_collector.flush_all_pending().await;

        let stats = db.stats().await.expect("database stats should be readable");
        assert_eq!(stats.total_events, 1);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn with_database_fails_when_sqlite_backend_cannot_initialize() {
        let mut config = EngineConfig::default();
        let bad_path =
            std::env::temp_dir().join(format!("nettrap-startup-bad-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&bad_path).unwrap();
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(bad_path.to_string_lossy().to_string());

        let startup = create_startup_context(&config, None).unwrap();
        let err = match with_database(startup, &config).await {
            Ok(_) => panic!("invalid sqlite target should fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("database initialization failed"));

        let _ = std::fs::remove_dir_all(&bad_path);
    }

    #[tokio::test]
    async fn with_database_fails_when_postgres_is_configured_without_url() {
        let mut config = EngineConfig::default();
        config.database.backend = "postgres".to_string();

        let startup = create_startup_context(&config, None).unwrap();
        let err = match with_database(startup, &config).await {
            Ok(_) => panic!("missing postgres url should fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("database initialization failed"));
        assert!(err.to_string().contains("postgres_url"));
    }

    #[test]
    fn create_startup_context_uses_configured_distributed_node_id() {
        let mut config = EngineConfig::default();
        config.distributed.node_id = Some("configured-node".to_string());

        let startup = create_startup_context(&config, None).unwrap();

        assert_eq!(startup.node_identity.node_id, "configured-node");
    }

    #[test]
    fn generated_node_identity_is_stable_without_explicit_node_id() {
        let first = crate::distributed::NodeIdentity::generate(None, None, Vec::new());
        let second = crate::distributed::NodeIdentity::generate(None, None, Vec::new());

        assert_eq!(first.node_id, second.node_id);
        assert_ne!(first.node_id, "unknown");
    }

    #[tokio::test]
    async fn with_database_preserves_explicit_database_node_id() {
        let mut config = EngineConfig::default();
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-startup-explicit-node-{}.db",
            uuid::Uuid::new_v4()
        ));
        config.distributed.node_id = Some("distributed-node".to_string());
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(db_path.to_string_lossy().to_string());
        config.database.node_id = Some("db-node".to_string());

        let startup = create_startup_context(&config, None).unwrap();
        let startup = with_database(startup, &config).await.unwrap();
        assert_eq!(startup.database_node_id.as_deref(), Some("db-node"));

        let db = startup
            .database
            .as_ref()
            .expect("database should be attached")
            .clone();
        let nbi = crate::nbi::raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &crate::session::SessionDestination::unknown(8080),
            4,
            "test",
        );
        startup.nbi_collector.record(&nbi).await;
        startup.nbi_collector.flush_all_pending().await;

        assert_eq!(db.load_events_for_node("db-node").await.unwrap().len(), 1);
        assert!(
            db.load_events_for_node("distributed-node")
                .await
                .unwrap()
                .is_empty()
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[test]
    fn create_startup_context_fails_when_output_path_resolves_to_directory() {
        let mut config = EngineConfig::default();
        let bad_parent = std::env::temp_dir().join(format!(
            "nettrap-startup-bad-output-parent-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&bad_parent, b"not-a-directory").unwrap();
        let bad_output = bad_parent.join("events.log");
        config.output_path = Some(bad_output.to_string_lossy().to_string());

        let err = match create_startup_context(&config, None) {
            Ok(_) => panic!("unwritable output path should fail startup"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("failed to create NBI output directory")
        );

        let _ = std::fs::remove_file(&bad_parent);
    }

    #[test]
    fn build_listener_context_propagates_log_hexdump() {
        let mut config = EngineConfig::default();
        config.log_hexdump = true;
        let startup = create_startup_context(&config, None).unwrap();
        let listener = config.listeners.first().unwrap();

        let ctx = build_listener_context(listener, &startup, None);

        assert!(ctx.config.log_hexdump);
    }

    #[test]
    fn init_protocol_router_keeps_defaults_unset_when_config_omits_them() {
        let config = EngineConfig::default();
        let defaults = validate_redirect_defaults(&config).unwrap();

        let router = init_protocol_router(&defaults);

        assert_eq!(router.default_tcp_handler(), None);
        assert_eq!(router.default_udp_handler(), None);
    }

    #[test]
    fn create_startup_context_rejects_invalid_redirect_default_listener() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("missing".into());

        let err = match create_startup_context(&config, None) {
            Ok(_) => panic!("startup should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn create_startup_context_rejects_unknown_distributed_sink_type() {
        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
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

        let err = match create_startup_context(&config, None) {
            Ok(_) => panic!("startup should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("Unknown distributed event sink type")
        );
    }

    #[tokio::test]
    async fn create_startup_context_starts_session_cleanup_and_attaches_tracker() {
        let config = EngineConfig::default();

        let startup = create_startup_context(&config, None).unwrap();

        assert!(startup.session_cleanup_task.is_some());
        assert_eq!(startup.session_tracker.active_count(), 0);
    }

    #[tokio::test]
    async fn init_distributed_does_not_spawn_tasks_when_disabled() {
        let mut config = EngineConfig::default();
        config.distributed.health_bind = Some("127.0.0.1:0".into());
        config.distributed.metrics_bind = Some("127.0.0.1:0".into());
        config.distributed.control_plane_url = Some("http://127.0.0.1:9999".into());
        config.distributed.heartbeat_interval_secs = 1;
        config.distributed.event_sinks = vec![crate::config::EventSinkConfig {
            sink_type: "http".into(),
            target: "http://127.0.0.1:9999".into(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        }];

        let node = Arc::new(crate::distributed::NodeIdentity::generate(
            None,
            None,
            Vec::new(),
        ));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (fatal_runtime_tx, _fatal_runtime_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut bg_tasks = Vec::new();

        init_distributed(
            &config,
            &node,
            &runtime_health,
            fatal_runtime_tx,
            &mut bg_tasks,
        )
        .unwrap();

        assert!(bg_tasks.is_empty());
    }

    #[tokio::test]
    async fn init_distributed_spawns_health_metrics_and_heartbeat_when_enabled() {
        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
        config.distributed.health_bind = Some("127.0.0.1:0".into());
        config.distributed.metrics_bind = Some("127.0.0.1:0".into());
        config.distributed.control_plane_url = Some("http://127.0.0.1:9999".into());
        config.distributed.heartbeat_interval_secs = 1;

        let node = Arc::new(crate::distributed::NodeIdentity::generate(
            None,
            None,
            Vec::new(),
        ));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (fatal_runtime_tx, _fatal_runtime_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut bg_tasks = Vec::new();

        init_distributed(
            &config,
            &node,
            &runtime_health,
            fatal_runtime_tx,
            &mut bg_tasks,
        )
        .unwrap();

        assert_eq!(bg_tasks.len(), 3);

        for task in bg_tasks {
            task.abort();
            let _ = task.await;
        }
    }

    #[tokio::test]
    async fn init_distributed_fails_when_health_bind_is_unavailable() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test socket");
        let bind = occupied.local_addr().expect("local addr").to_string();

        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
        config.distributed.health_bind = Some(bind);

        let node = Arc::new(crate::distributed::NodeIdentity::generate(
            None,
            None,
            Vec::new(),
        ));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (fatal_runtime_tx, _fatal_runtime_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut bg_tasks = Vec::new();

        let err = init_distributed(
            &config,
            &node,
            &runtime_health,
            fatal_runtime_tx,
            &mut bg_tasks,
        )
        .expect_err("bind conflict should fail startup");

        assert!(err.to_string().contains("health/readiness"));
    }
}
