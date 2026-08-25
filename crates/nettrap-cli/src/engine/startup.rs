use std::path::PathBuf;
use std::sync::Arc;

#[cfg(test)]
pub(crate) use super::background::report_background_service_exit;
pub use super::background::{init_distributed, init_faketime};
pub use super::platform::{init_windows_ca_trust, init_windows_network};
#[cfg(test)]
pub(crate) use super::platform::{should_modify_local_dns, tls_ca_cert_path};
use crate::config::EngineConfig;
use crate::database::DatabaseBackend;

mod cleanup;
mod database;
mod listener_context;
mod output;
mod pcap;
mod redirects;
mod tls;
use cleanup::start_runtime_cleanup_task;
pub(crate) use database::with_database;
pub(crate) use listener_context::build_listener_context;
use output::validate_output_file_path;
#[cfg(test)]
use pcap::default_pcap_path;
use pcap::init_pcap_writer;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) use redirects::resolve_default_listener_port;
use redirects::{ValidatedRedirectDefaults, init_protocol_router, validate_redirect_defaults};
use tls::init_tls_ca;

pub struct StartupContext {
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    pub attribution_timeout: std::time::Duration,
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    pub flow_manager: Arc<nettrap_flow::FlowManager>,
    pub runtime_health: Arc<nettrap_engine::RuntimeHealth>,
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
    pub smtp_dir: Option<PathBuf>,
    pub log_hexdump: bool,
    pub global_process_whitelist: Vec<String>,
    pub global_process_blacklist: Vec<String>,
    pub windows_ca_trust_thumbprint: Option<String>,
}

pub use nettrap_engine::StartupMode;

#[cfg(test)]
pub fn create_startup_context(
    config: &EngineConfig,
    output_override: Option<PathBuf>,
    mode: StartupMode,
) -> crate::Result<StartupContext> {
    create_startup_context_with_overrides(config, output_override, None, mode)
}

pub fn create_startup_context_with_overrides(
    config: &EngineConfig,
    output_override: Option<PathBuf>,
    pcap_override: Option<PathBuf>,
    mode: StartupMode,
) -> crate::Result<StartupContext> {
    let listener_driven_outputs_enabled = mode.listener_driven_outputs_enabled();
    let distributed_enabled = listener_driven_outputs_enabled && config.distributed.enabled;
    let redirect_defaults = if listener_driven_outputs_enabled {
        validate_redirect_defaults(config)?
    } else {
        ValidatedRedirectDefaults::default()
    };
    let ca = if listener_driven_outputs_enabled {
        init_tls_ca(config)?
    } else {
        None
    };
    let router = init_protocol_router(&redirect_defaults);
    let attribution = init_attribution(config);
    let attribution_timeout = std::time::Duration::from_millis(config.attribution_timeout_ms);
    let pcap_writer = if listener_driven_outputs_enabled {
        init_pcap_writer(config, pcap_override.as_deref())?
    } else {
        None
    };

    let output_path = if listener_driven_outputs_enabled {
        output_override.clone().or_else(|| {
            config.output_path.as_deref().and_then(|value| {
                let trimmed = value.trim_matches([' ', '\t']);
                if trimmed.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(value))
                }
            })
        })
    } else {
        None
    };

    let nbi_path = if listener_driven_outputs_enabled {
        if let Some(ref output_path) = output_path {
            validate_output_file_path(output_path)?;
        }
        output_path.clone()
    } else {
        None
    };

    let node_identity = Arc::new(crate::distributed::NodeIdentity::generate_with_now(
        config.distributed.node_id.clone(),
        config.distributed.node_region.clone(),
        config.distributed.node_tags.clone(),
        crate::faketime::fake_now,
    ));
    let run_id = uuid::Uuid::new_v4().to_string();

    let flow_manager =
        Arc::new(nettrap_flow::FlowManager::default().with_now(crate::faketime::fake_now));
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    let nbi_collector = Arc::new(crate::nbi::NbiCollector::new(nbi_path.clone())?);
    nbi_collector.attach_runtime_health(runtime_health.clone());
    if distributed_enabled {
        let fanout = Arc::new(crate::distributed::build_event_fanout(&config.distributed)?);
        for name in fanout.sink_names() {
            tracing::info!("Event sink registered: {}", name);
        }
        fanout.attach_runtime_health(runtime_health.clone());
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
    nbi_collector.attach_session_tracker(Arc::clone(&session_tracker));
    if listener_driven_outputs_enabled {
        let listener_protocols = config
            .listeners
            .iter()
            .map(|listener| (listener.name.clone(), listener.protocol))
            .collect();
        nbi_collector.attach_listener_protocols(listener_protocols);
    }

    Ok(StartupContext {
        ca,
        router,
        attribution,
        attribution_timeout,
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
        http_post_dump_dir: config.http_post_dump_dir.as_deref().and_then(|value| {
            let trimmed = value.trim_matches([' ', '\t']);
            if trimmed.is_empty() {
                None
            } else {
                Some(value.to_owned())
            }
        }),
        smtp_dir: config.smtp_dir.as_deref().map(PathBuf::from),
        log_hexdump: config.log_hexdump,
        global_process_whitelist: config.global_process_whitelist.clone(),
        global_process_blacklist: config.global_process_blacklist.clone(),
        windows_ca_trust_thumbprint: None,
    })
}

fn init_attribution(config: &EngineConfig) -> Option<Arc<nettrap_attribution::AttributionEngine>> {
    if config.attribution_enabled {
        Some(Arc::new(
            nettrap_attribution::AttributionEngine::with_cache_timeout(
                std::time::Duration::from_millis(config.attribution_timeout_ms),
            ),
        ))
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::config::ListenerConfig;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use tokio::sync::mpsc;

    #[test]
    fn should_modify_local_dns_honors_explicit_config_flag() {
        let mut config = EngineConfig::default();
        config.modify_local_dns = true;

        assert!(should_modify_local_dns(&config));
    }

    #[test]
    fn should_modify_local_dns_keeps_legacy_debug_flag_compatibility() {
        let mut config = EngineConfig::default();
        config.debug_flags = vec!["fixdns".to_string()];

        assert!(should_modify_local_dns(&config));
    }

    #[test]
    fn resolve_default_listener_port_handles_unicode_case_folding() {
        let mut config = EngineConfig::default();
        config.listeners = vec![ListenerConfig::new("MÜLLER", 8080)];

        assert_eq!(
            resolve_default_listener_port(&config, "müller", nettrap_core::prelude::Protocol::Tcp),
            Some(8080)
        );
    }

    #[tokio::test]
    async fn with_database_attaches_backend_to_nbi_collector() {
        let mut config = EngineConfig::default();
        let db_path =
            std::env::temp_dir().join(format!("nettrap-startup-test-{}.db", uuid::Uuid::new_v4()));
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(db_path.clone());

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
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

    #[test]
    fn default_pcap_path_is_unique_without_clock_dependency() {
        let first = default_pcap_path("packets");
        let second = default_pcap_path("packets");

        assert_ne!(first, second);
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("pcap"));
        assert_eq!(
            second.extension().and_then(|ext| ext.to_str()),
            Some("pcap")
        );
    }

    #[test]
    fn create_startup_context_rejects_path_like_pcap_prefix() {
        let mut config = EngineConfig::default();
        config.pcap_enabled = true;
        config.pcap_prefix = Some("../escape".to_string());

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("path-like pcap_prefix should fail startup"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("pcap_prefix must be a single file name component")
        );

        config.pcap_prefix = Some("nested/capture".to_string());
        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("separator in pcap_prefix should fail startup"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("pcap_prefix must be a single file name component")
        );
    }

    #[tokio::test]
    async fn with_database_fails_when_sqlite_backend_cannot_initialize() {
        let mut config = EngineConfig::default();
        let bad_path =
            std::env::temp_dir().join(format!("nettrap-startup-bad-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&bad_path).unwrap();
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(bad_path.clone());

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
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

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
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

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();

        assert_eq!(startup.node_identity.node_id, "configured-node");
    }

    #[test]
    fn generated_node_identity_is_stable_without_explicit_node_id() {
        let first = crate::distributed::NodeIdentity::generate(None, None, Vec::new());
        let second = crate::distributed::NodeIdentity::generate(None, None, Vec::new());

        assert_eq!(first.node_id, second.node_id);
        assert_ne!(first.node_id, "unknown");
    }

    #[cfg(unix)]
    #[test]
    fn tls_ca_cert_path_preserves_non_utf8_directory_bytes() {
        let dir = OsString::from_vec(vec![b'n', b'e', b't', b't', b'r', b'a', b'p', 0xff]);

        let path = tls_ca_cert_path(&dir);

        assert_eq!(path, std::path::PathBuf::from(dir).join("ca.crt"));
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
        config.database.sqlite_path = Some(db_path.clone());
        config.database.node_id = Some("db-node".to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
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

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn with_database_preserves_non_utf8_sqlite_path_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let mut config = EngineConfig::default();
        let root =
            std::env::temp_dir().join(format!("nettrap-startup-nonutf8-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join(std::ffi::OsString::from_vec(b"nbi-\xff.db".to_vec()));
        config.database.backend = "sqlite".to_string();
        config.database.sqlite_path = Some(db_path.clone());

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
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
        let _ = std::fs::remove_dir_all(root);
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

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("unwritable output path should fail startup"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("failed to create output directory")
        );

        let _ = std::fs::remove_file(&bad_parent);
    }

    #[cfg(unix)]
    #[test]
    fn create_startup_context_rejects_symlinked_output_path() {
        let mut config = EngineConfig::default();
        let root = std::env::temp_dir().join(format!(
            "nettrap-startup-symlink-output-{}",
            uuid::Uuid::new_v4()
        ));
        let real_parent = root.join("real");
        std::fs::create_dir_all(&real_parent).unwrap();
        let target = real_parent.join("events.log");
        std::fs::write(&target, "existing").unwrap();
        let link = root.join("events.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        config.output_path = Some(link.to_string_lossy().to_string());

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("symlinked output path should fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("is a symlink"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "existing");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_listener_context_propagates_log_hexdump() {
        let mut config = EngineConfig::default();
        config.log_hexdump = true;
        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
        let listener = config.listeners.first().unwrap();

        let ctx = build_listener_context(listener, &startup, None).expect("build listener context");

        assert!(ctx.config.log_hexdump);
    }

    #[test]
    fn build_listener_context_propagates_attribution_timeout() {
        let mut config = EngineConfig::default();
        config.attribution_timeout_ms = 1234;
        config.listeners = vec![crate::config::ListenerConfig::new("raw", 9000)];
        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();
        let listener = config.listeners.first().unwrap();

        let ctx = build_listener_context(listener, &startup, None).expect("build listener context");

        assert_eq!(
            ctx.runtime.attribution_timeout,
            std::time::Duration::from_millis(1234)
        );
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

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("startup should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn create_startup_context_rejects_ambiguous_redirect_default_listener() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("raw".into());
        config.listeners = vec![
            crate::config::ListenerConfig::new("raw", 9000),
            crate::config::ListenerConfig::new("raw", 9001),
        ];

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("ambiguous redirect default should fail startup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("unambiguous"));
        assert!(err.to_string().contains("raw"));
    }

    #[test]
    fn create_startup_context_ignores_blank_redirect_default_listener_when_other_is_valid() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some(" ".into());
        config.default_udp_listener = Some("dns".into());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("blank TCP default should be ignored when UDP default is valid");

        assert_eq!(startup.router.default_tcp_handler(), None);
        assert_eq!(startup.router.default_udp_handler(), Some("dns"));
    }

    #[test]
    fn create_startup_context_uses_handler_names_for_redirect_router_defaults() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("control".into());
        config.default_udp_listener = Some("echo_7".into());
        let mut udp_default = crate::config::ListenerConfig::new("echo_7", 9001);
        udp_default.protocol = nettrap_core::prelude::Protocol::Udp;
        config.listeners = vec![
            crate::config::ListenerConfig::new("control", 9000),
            udp_default,
        ];

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("redirect defaults should resolve to spawnable listeners");

        assert_eq!(startup.router.default_tcp_handler(), Some("raw"));
        assert_eq!(startup.router.default_udp_handler(), Some("raw"));
    }

    #[test]
    fn create_startup_context_rejects_unicode_whitespace_padded_redirect_default_listener() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("fallback\u{00a0}".into());
        config.default_udp_listener = Some("dns".into());

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
            Ok(_) => panic!("unicode padded redirect default should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("invalid"));
        assert!(err.to_string().contains("fallback"));
    }

    #[test]
    fn create_startup_context_api_only_skips_redirect_validation() {
        let mut config = EngineConfig::default();
        config.redirect_all_traffic = true;
        config.default_tcp_listener = Some("missing".into());

        create_startup_context(&config, None, StartupMode::ApiOnly)
            .expect("api-only startup should ignore listener redirect defaults");
    }

    #[test]
    fn create_startup_context_api_only_skips_tls_ca_initialization() {
        let mut config = EngineConfig::default();
        config.listeners = vec![crate::config::ListenerConfig::https()];
        config.tls_ca_cert = Some("/definitely/missing/nettrap-ca.pem".into());
        config.tls_ca_key = Some("/definitely/missing/nettrap-ca-key.pem".into());

        let startup = create_startup_context(&config, None, StartupMode::ApiOnly)
            .expect("api-only startup should skip TLS CA setup");

        assert!(startup.ca.is_none());
    }

    #[test]
    fn tls_ca_cert_path_joins_directory_without_string_concatenation() {
        let cert_path = tls_ca_cert_path("certs/");

        assert_eq!(cert_path, std::path::Path::new("certs").join("ca.crt"));
    }

    #[test]
    fn create_startup_context_api_only_skips_listener_driven_outputs_and_metadata() {
        let mut config = EngineConfig::default();
        config.pcap_enabled = true;
        config.output_path = Some("events.jsonl".into());
        config.listeners = vec![
            crate::config::ListenerConfig::new("dup", 80),
            crate::config::ListenerConfig::new("dup", 81),
        ];

        let startup = create_startup_context(&config, None, StartupMode::ApiOnly)
            .expect("api-only startup should skip capture outputs");

        assert!(startup.pcap_writer.is_none());
        assert!(startup.output_path.is_none());
        assert!(startup.nbi_path.is_none());
        assert_eq!(startup.nbi_collector.listener_protocol_count(), 0);
    }

    #[test]
    fn create_startup_context_api_only_disables_distributed_export_even_when_configured() {
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

        let startup = create_startup_context(&config, None, StartupMode::ApiOnly)
            .expect("api-only startup should ignore distributed export config");

        assert_eq!(
            startup.runtime_health.snapshot().distributed_export.state,
            nettrap_api::ComponentState::Disabled
        );
    }

    #[test]
    fn create_startup_context_preserves_exact_output_path_for_nbi() {
        let mut config = EngineConfig::default();
        config.output_path = Some(
            std::env::temp_dir()
                .join(format!(
                    "nettrap-output-preserve-{}.jsonl",
                    uuid::Uuid::new_v4()
                ))
                .to_string_lossy()
                .to_string(),
        );

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("startup should initialize with explicit output path");

        assert!(startup.output_path.is_some());
        assert_eq!(startup.output_path, startup.nbi_path);
    }

    #[test]
    fn create_startup_context_does_not_materialize_output_file_during_validation() {
        let root =
            std::env::temp_dir().join(format!("nettrap-output-validate-{}", uuid::Uuid::new_v4()));
        let output = root.join("nested").join("events.jsonl");
        let mut config = EngineConfig::default();
        config.output_path = Some(output.to_string_lossy().to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("startup should initialize with explicit output path");

        assert!(startup.output_path.is_some());
        assert!(!output.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn create_startup_context_accepts_output_path_trailing_current_dir_component() {
        let root =
            std::env::temp_dir().join(format!("nettrap-output-curdir-{}", uuid::Uuid::new_v4()));
        let output = root.join("events.jsonl");
        let mut config = EngineConfig::default();
        config.output_path = Some(output.join(".").to_string_lossy().to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("trailing current-dir output path should initialize");

        assert!(startup.output_path.is_some());
        assert!(!output.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn create_startup_context_ignores_blank_output_path_and_dump_dir() {
        let mut config = EngineConfig::default();
        config.output_path = Some("   ".to_string());
        config.http_post_dump_dir = Some("\t".to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("blank output_path and dump dir should be ignored");

        assert!(startup.output_path.is_none());
        assert!(startup.nbi_path.is_none());
        assert!(startup.http_post_dump_dir.is_none());
    }

    #[test]
    fn create_startup_context_preserves_smtp_directory() {
        let mut config = EngineConfig::default();
        config.smtp_dir = Some("mail-capture".to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("configured SMTP directory should be accepted");

        assert_eq!(
            startup.smtp_dir.as_deref(),
            Some(std::path::Path::new("mail-capture"))
        );
    }

    #[test]
    fn create_startup_context_ignores_unicode_whitespace_output_path() {
        let mut config = EngineConfig::default();
        config.output_path = Some("output\u{00a0}.jsonl".to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("unicode whitespace output_path should be preserved");

        assert_eq!(
            startup.output_path.as_deref(),
            Some(std::path::Path::new("output\u{00a0}.jsonl"))
        );
        assert_eq!(startup.output_path, startup.nbi_path);
    }

    #[test]
    fn create_startup_context_preserves_ascii_spaced_output_path() {
        let mut config = EngineConfig::default();
        config.output_path = Some("  events.jsonl  ".to_string());
        config.http_post_dump_dir = Some("  dump dir  ".to_string());

        let startup = create_startup_context(&config, None, StartupMode::Standard)
            .expect("startup should preserve spaced output path");

        assert_eq!(
            startup.output_path.as_deref(),
            Some(std::path::Path::new("  events.jsonl  "))
        );
        assert_eq!(startup.http_post_dump_dir.as_deref(), Some("  dump dir  "));
        assert_eq!(startup.output_path, startup.nbi_path);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn create_startup_context_preserves_non_utf8_pcap_path_override() {
        let root =
            std::env::temp_dir().join(format!("nettrap-pcap-override-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let pcap_path = root.join(OsString::from_vec(b"capture-\xff.pcap".to_vec()));

        let mut config = EngineConfig::default();
        config.pcap_enabled = true;

        let startup = create_startup_context_with_overrides(
            &config,
            None,
            Some(pcap_path.clone()),
            StartupMode::Standard,
        )
        .expect("startup should preserve non-UTF8 pcap override");

        assert!(startup.pcap_writer.is_some());
        assert!(pcap_path.exists());

        let _ = std::fs::remove_file(&pcap_path);
        let _ = std::fs::remove_dir_all(root);
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

        let err = match create_startup_context(&config, None, StartupMode::Standard) {
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

        let startup = create_startup_context(&config, None, StartupMode::Standard).unwrap();

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
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
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
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
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
    async fn init_distributed_rejects_heartbeat_without_control_plane_url() {
        let mut config = EngineConfig::default();
        config.distributed.enabled = true;
        config.distributed.heartbeat_interval_secs = 1;

        let node = Arc::new(crate::distributed::NodeIdentity::generate(
            None,
            None,
            Vec::new(),
        ));
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
        let (fatal_runtime_tx, _fatal_runtime_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut bg_tasks = Vec::new();

        let err = init_distributed(
            &config,
            &node,
            &runtime_health,
            fatal_runtime_tx,
            &mut bg_tasks,
        )
        .expect_err("heartbeat without control plane URL should fail startup");

        assert!(err.to_string().contains(
            "distributed.heartbeat_interval_secs requires distributed.control_plane_url"
        ));
        assert!(bg_tasks.is_empty());
    }

    #[tokio::test]
    async fn report_background_service_exit_marks_ok_completion_as_failed() {
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
        let (fatal_runtime_tx, mut fatal_runtime_rx) = mpsc::unbounded_channel();

        report_background_service_exit(
            "Heartbeat",
            "heartbeat failed: ".to_string(),
            Ok::<(), nettrap_distributed::Error>(()),
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
        );

        assert_eq!(
            runtime_health.snapshot().fatal_error.as_deref(),
            Some("Heartbeat exited unexpectedly")
        );
        assert_eq!(
            fatal_runtime_rx.recv().await.as_deref(),
            Some("Heartbeat exited unexpectedly")
        );
    }

    #[tokio::test]
    async fn report_background_service_exit_formats_errors_with_prefix() {
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
        let (fatal_runtime_tx, mut fatal_runtime_rx) = mpsc::unbounded_channel();

        report_background_service_exit(
            "Heartbeat",
            "heartbeat failed: ".to_string(),
            Err(nettrap_distributed::Error::Other(
                "network down".to_string(),
            )),
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
        );

        assert_eq!(
            runtime_health.snapshot().fatal_error.as_deref(),
            Some("heartbeat failed: network down")
        );
        assert_eq!(
            fatal_runtime_rx.recv().await.as_deref(),
            Some("heartbeat failed: network down")
        );
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
        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
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

    #[test]
    fn init_faketime_skips_auto_increment_when_disabled_by_interval() {
        let mut config = EngineConfig::default();
        config.faketime.enabled = true;
        config.faketime.auto_delay_secs = 0;
        config.faketime.auto_increment_secs = 60;

        let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
        let (fatal_runtime_tx, _fatal_runtime_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut bg_tasks = Vec::new();

        init_faketime(
            &config,
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
            &mut bg_tasks,
        );

        assert!(bg_tasks.is_empty());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn init_windows_ca_trust_returns_none_without_windows_install() {
        let mut config = EngineConfig::default();
        config.tls_cert_dir = Some(std::env::temp_dir().to_string_lossy().to_string());

        assert!(init_windows_ca_trust(&config).is_none());
    }
}
