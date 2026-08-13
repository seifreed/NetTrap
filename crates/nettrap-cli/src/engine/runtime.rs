use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use nettrap_engine::{RuntimeHost, RuntimePlan, RuntimeRunner};

use crate::config::EngineConfig;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::engine::api::start_api_server;
use crate::engine::config_load::validate_adapter_configuration;
use crate::engine::interceptor::{RunningInterceptor, spawn_interceptor};
use crate::engine::lifecycle::{shutdown_and_return, shutdown_runtime, wait_for_shutdown};
use crate::engine::spawn::spawn_listeners;
use crate::engine::startup::{
    StartupContext, init_distributed, init_faketime, init_windows_ca_trust, init_windows_network,
    with_database,
};

pub(super) struct EngineOptions {
    pub(super) intercept_enabled: bool,
    pub(super) require_interceptor: bool,
    pub(super) plan: RuntimePlan,
    pub(super) interface: Option<String>,
    pub(super) output_override: Option<PathBuf>,
    pub(super) pcap_override: Option<PathBuf>,
}

pub struct Engine {
    pub(super) config: EngineConfig,
    pub(super) options: EngineOptions,
}

impl Engine {
    pub fn new(
        config: EngineConfig,
        intercept_enabled: bool,
        interface: Option<String>,
        output_override: Option<PathBuf>,
        pcap_override: Option<PathBuf>,
        require_interceptor: bool,
        allow_zero_listeners: bool,
    ) -> Self {
        Self {
            config,
            options: EngineOptions {
                intercept_enabled,
                require_interceptor,
                plan: RuntimePlan::standard(allow_zero_listeners),
                interface,
                output_override,
                pcap_override,
            },
        }
    }

    pub fn api_only(config: EngineConfig) -> Self {
        Self {
            config,
            options: EngineOptions {
                intercept_enabled: false,
                require_interceptor: false,
                plan: RuntimePlan::api_only(),
                interface: None,
                output_override: None,
                pcap_override: None,
            },
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub async fn run(&self, stop_flag: Option<std::path::PathBuf>) -> crate::Result<()> {
        tracing::info!("Starting NetTrap engine...");
        let (fatal_runtime_tx, fatal_runtime_rx) = mpsc::unbounded_channel::<String>();
        let host = CliRuntimeHost {
            engine: self,
            fatal_runtime_tx,
            fatal_runtime_rx,
        };

        RuntimeRunner::new(host, self.options.plan)
            .run(stop_flag)
            .await
            .map_err(crate::Error::from)
    }

    fn prepare_config(&self, plan: RuntimePlan) -> crate::Result<EngineConfig> {
        let listener_driven_outputs_enabled = plan.listener_driven_outputs_enabled();
        let mut config = self.config.clone();
        if listener_driven_outputs_enabled {
            config.prepare_runtime_defaults()?;
            validate_adapter_configuration(&config)?;
        } else {
            config.prepare_api_defaults()?;
        }

        log_network_mode(&config);
        if listener_driven_outputs_enabled {
            log_redirect_mode(&config);
        }

        Ok(config)
    }

    async fn initialize_startup(
        &self,
        config: &EngineConfig,
        plan: RuntimePlan,
    ) -> crate::Result<StartupContext> {
        if plan.listener_driven_outputs_enabled() {
            init_windows_network(config);
        }

        let startup = crate::engine::startup::create_startup_context_with_overrides(
            config,
            self.options.output_override.clone(),
            self.options.pcap_override.clone(),
            plan.mode(),
        )?;
        let mut startup = with_database(startup, config).await?;
        if plan.listener_driven_outputs_enabled() {
            startup.windows_ca_trust_thumbprint = init_windows_ca_trust(config);
        }
        startup
            .runtime_health
            .set_allow_zero_listeners(plan.allow_zero_listeners());
        Ok(startup)
    }

    async fn start_background_services(
        &self,
        config: &EngineConfig,
        startup: &mut StartupContext,
        fatal_runtime_tx: mpsc::UnboundedSender<String>,
        plan: RuntimePlan,
    ) -> crate::Result<()> {
        if plan.listener_driven_outputs_enabled() {
            if let Err(err) = init_distributed(
                config,
                &startup.node_identity,
                &startup.runtime_health,
                fatal_runtime_tx.clone(),
                &mut startup.background_tasks,
            ) {
                startup.runtime_health.set_fatal_error(err.to_string());
                return Err(err);
            }
            init_faketime(
                config,
                Arc::clone(&startup.runtime_health),
                fatal_runtime_tx.clone(),
                &mut startup.background_tasks,
            );
        }

        Ok(())
    }

    async fn start_api(
        &self,
        config: &EngineConfig,
        startup: &mut StartupContext,
        fatal_runtime_tx: mpsc::UnboundedSender<String>,
    ) -> crate::Result<()> {
        startup.runtime_health.set_api_disabled();
        if let Some(bind) = config.api_bind.as_ref()
            && let Err(err) = start_api_server(
                bind,
                Arc::clone(&startup.flow_manager),
                Arc::clone(&startup.runtime_health),
                fatal_runtime_tx,
                &mut startup.background_tasks,
            )
            .await
        {
            startup.runtime_health.set_api_failed(err.to_string());
            return Err(err);
        }

        Ok(())
    }

    async fn start_interceptor(
        &self,
        config: &EngineConfig,
        startup: &mut StartupContext,
        fatal_runtime_tx: mpsc::UnboundedSender<String>,
    ) -> crate::Result<Option<RunningInterceptor>> {
        if !self.options.intercept_enabled {
            startup.runtime_health.set_interceptor_disabled();
            return Ok(None);
        }

        startup.runtime_health.set_interceptor_starting();
        match spawn_interceptor(
            config,
            self.options.interface.clone(),
            self.options.output_override.clone(),
            Arc::clone(&startup.port_forward_table),
            Arc::clone(&startup.runtime_health),
            fatal_runtime_tx,
        )
        .await
        {
            Ok(Some(handle)) => Ok(Some(handle)),
            Ok(None) if self.options.require_interceptor => {
                let message = "Interception was requested but no interceptor could be started";
                startup.runtime_health.set_interceptor_failed(message);
                Err(crate::Error::Other(message.to_string()))
            }
            Ok(None) => Ok(None),
            Err(err) => {
                startup
                    .runtime_health
                    .set_interceptor_failed(err.to_string());
                Err(err)
            }
        }
    }
}

struct CliRuntimeHost<'a> {
    engine: &'a Engine,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
    fatal_runtime_rx: mpsc::UnboundedReceiver<String>,
}

#[async_trait]
impl RuntimeHost for CliRuntimeHost<'_> {
    type Config = EngineConfig;
    type Context = StartupContext;
    type ListenerHandles = Vec<JoinHandle<crate::Result<()>>>;
    type Interceptor = RunningInterceptor;
    type StopFlag = PathBuf;

    async fn prepare_config(&mut self, plan: RuntimePlan) -> nettrap_core::Result<Self::Config> {
        self.engine.prepare_config(plan).map_err(to_core_error)
    }

    fn has_spawnable_listeners(&self, config: &Self::Config) -> bool {
        crate::engine::spawn::has_spawnable_listeners(config)
    }

    async fn initialize(
        &mut self,
        config: &Self::Config,
        plan: RuntimePlan,
    ) -> nettrap_core::Result<Self::Context> {
        self.engine
            .initialize_startup(config, plan)
            .await
            .map_err(to_core_error)
    }

    async fn start_background_services(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        plan: RuntimePlan,
    ) -> nettrap_core::Result<()> {
        self.engine
            .start_background_services(config, context, self.fatal_runtime_tx.clone(), plan)
            .await
            .map_err(to_core_error)
    }

    async fn start_api(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
    ) -> nettrap_core::Result<()> {
        self.engine
            .start_api(config, context, self.fatal_runtime_tx.clone())
            .await
            .map_err(to_core_error)
    }

    async fn start_interceptor(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
    ) -> nettrap_core::Result<Option<Self::Interceptor>> {
        self.engine
            .start_interceptor(config, context, self.fatal_runtime_tx.clone())
            .await
            .map_err(to_core_error)
    }

    async fn start_listeners(
        &mut self,
        config: &Self::Config,
        context: &Self::Context,
    ) -> nettrap_core::Result<Self::ListenerHandles> {
        spawn_listeners(
            config,
            context,
            Arc::clone(&context.runtime_health),
            self.fatal_runtime_tx.clone(),
        )
        .await
        .map_err(to_core_error)
    }

    fn mark_startup_complete(
        &mut self,
        context: &mut Self::Context,
        listener_handles: &Self::ListenerHandles,
        interceptor: Option<&Self::Interceptor>,
    ) {
        context.runtime_health.mark_startup_complete();
        let task_count = listener_handles.len() + usize::from(interceptor.is_some());
        tracing::info!("Engine running with {} tasks", task_count);
    }

    async fn shutdown_on_startup_error(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        listener_handles: Self::ListenerHandles,
        interceptor: Option<Self::Interceptor>,
        error: nettrap_core::Error,
        phase: &'static str,
    ) -> nettrap_core::Result<()> {
        shutdown_and_return(
            context,
            config,
            listener_handles,
            interceptor,
            crate::Error::from(error),
            phase,
        )
        .await
        .map_err(to_core_error)
    }

    async fn wait_for_shutdown(
        &mut self,
        stop_flag: Option<Self::StopFlag>,
    ) -> nettrap_engine::ShutdownReason {
        wait_for_shutdown(stop_flag, &mut self.fatal_runtime_rx).await
    }

    async fn shutdown(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        listener_handles: Self::ListenerHandles,
        interceptor: Option<Self::Interceptor>,
    ) -> Option<nettrap_core::Error> {
        shutdown_runtime(context, config, listener_handles, interceptor)
            .await
            .map(to_core_error)
    }
}

fn to_core_error(error: crate::Error) -> nettrap_core::Error {
    match error {
        crate::Error::Core(error) => error,
        crate::Error::Io(error) => error.into(),
        crate::Error::Config(message) => nettrap_core::Error::Config(message),
        crate::Error::Other(message) => nettrap_core::Error::Runtime(message),
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
