use async_trait::async_trait;

use crate::{RuntimePlan, ShutdownReason};

/// Port implemented by a composition root for the runtime lifecycle.
///
/// The associated types keep infrastructure details outside this crate. The
/// runner owns lifecycle order and failure policy; the host owns sockets,
/// tasks, interception, storage, and platform-specific cleanup.
#[async_trait]
pub trait RuntimeHost: Send {
    type Config: Send + Sync;
    type Context: Send;
    type ListenerHandles: Default + Send;
    type Interceptor: Send;
    type StopFlag: Send;

    async fn prepare_config(&mut self, plan: RuntimePlan) -> nettrap_core::Result<Self::Config>;

    fn has_spawnable_listeners(&self, config: &Self::Config) -> bool;

    async fn initialize(
        &mut self,
        config: &Self::Config,
        plan: RuntimePlan,
    ) -> nettrap_core::Result<Self::Context>;

    async fn start_background_services(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        plan: RuntimePlan,
    ) -> nettrap_core::Result<()>;

    async fn start_api(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
    ) -> nettrap_core::Result<()>;

    async fn start_interceptor(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
    ) -> nettrap_core::Result<Option<Self::Interceptor>>;

    async fn start_listeners(
        &mut self,
        config: &Self::Config,
        context: &Self::Context,
    ) -> nettrap_core::Result<Self::ListenerHandles>;

    fn mark_startup_complete(
        &mut self,
        context: &mut Self::Context,
        listener_handles: &Self::ListenerHandles,
        interceptor: Option<&Self::Interceptor>,
    );

    async fn shutdown_on_startup_error(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        listener_handles: Self::ListenerHandles,
        interceptor: Option<Self::Interceptor>,
        error: nettrap_core::Error,
        phase: &'static str,
    ) -> nettrap_core::Result<()>;

    async fn wait_for_shutdown(&mut self, stop_flag: Option<Self::StopFlag>) -> ShutdownReason;

    async fn shutdown(
        &mut self,
        config: &Self::Config,
        context: &mut Self::Context,
        listener_handles: Self::ListenerHandles,
        interceptor: Option<Self::Interceptor>,
    ) -> Option<nettrap_core::Error>;
}

/// Runs the runtime use case through an adapter-provided host.
pub struct RuntimeRunner<H> {
    host: H,
    plan: RuntimePlan,
}

impl<H> RuntimeRunner<H> {
    pub const fn new(host: H, plan: RuntimePlan) -> Self {
        Self { host, plan }
    }
}

impl<H> RuntimeRunner<H>
where
    H: RuntimeHost,
{
    pub async fn run(mut self, stop_flag: Option<H::StopFlag>) -> nettrap_core::Result<()> {
        let config = self.host.prepare_config(self.plan).await?;
        let has_spawnable_listeners = self.host.has_spawnable_listeners(&config);
        crate::validate_listener_presence(
            self.plan.mode(),
            self.plan.allow_zero_listeners(),
            has_spawnable_listeners,
        )?;

        let mut context = self.host.initialize(&config, self.plan).await?;
        let mut listener_handles = H::ListenerHandles::default();

        if let Err(error) = self
            .host
            .start_background_services(&config, &mut context, self.plan)
            .await
        {
            return self
                .host
                .shutdown_on_startup_error(
                    &config,
                    &mut context,
                    listener_handles,
                    None,
                    error,
                    "distributed startup failure",
                )
                .await;
        }

        if let Err(error) = self.host.start_api(&config, &mut context).await {
            return self
                .host
                .shutdown_on_startup_error(
                    &config,
                    &mut context,
                    listener_handles,
                    None,
                    error,
                    "API startup failure",
                )
                .await;
        }

        let interceptor = match self.host.start_interceptor(&config, &mut context).await {
            Ok(interceptor) => interceptor,
            Err(error) => {
                return self
                    .host
                    .shutdown_on_startup_error(
                        &config,
                        &mut context,
                        listener_handles,
                        None,
                        error,
                        "interceptor startup failure",
                    )
                    .await;
            }
        };

        if self.plan.listener_driven_outputs_enabled() {
            listener_handles = match self.host.start_listeners(&config, &context).await {
                Ok(handles) => handles,
                Err(error) => {
                    return self
                        .host
                        .shutdown_on_startup_error(
                            &config,
                            &mut context,
                            listener_handles,
                            interceptor,
                            error,
                            "listener startup failure",
                        )
                        .await;
                }
            };
        }

        self.host
            .mark_startup_complete(&mut context, &listener_handles, interceptor.as_ref());
        let shutdown_reason = self.host.wait_for_shutdown(stop_flag).await;
        if let Some(error) = self
            .host
            .shutdown(&config, &mut context, listener_handles, interceptor)
            .await
        {
            return Err(error);
        }

        match shutdown_reason {
            ShutdownReason::Fatal(message) => Err(nettrap_core::Error::Runtime(message)),
            ShutdownReason::Signal | ShutdownReason::StopFlag => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct FakeHost {
        events: Arc<Mutex<Vec<&'static str>>>,
        spawnable: bool,
        fail_background: bool,
        fail_api: bool,
        fail_interceptor: bool,
        fail_listeners: bool,
    }

    struct FakeConfig {
        spawnable: bool,
    }

    #[derive(Default)]
    struct FakeContext;

    #[derive(Default)]
    struct FakeListeners;

    struct FakeInterceptor;

    impl FakeHost {
        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[async_trait]
    impl RuntimeHost for FakeHost {
        type Config = FakeConfig;
        type Context = FakeContext;
        type ListenerHandles = FakeListeners;
        type Interceptor = FakeInterceptor;
        type StopFlag = ();

        async fn prepare_config(
            &mut self,
            _plan: RuntimePlan,
        ) -> nettrap_core::Result<Self::Config> {
            self.record("prepare");
            Ok(FakeConfig {
                spawnable: self.spawnable,
            })
        }

        fn has_spawnable_listeners(&self, config: &Self::Config) -> bool {
            config.spawnable
        }

        async fn initialize(
            &mut self,
            _config: &Self::Config,
            _plan: RuntimePlan,
        ) -> nettrap_core::Result<Self::Context> {
            self.record("initialize");
            Ok(FakeContext)
        }

        async fn start_background_services(
            &mut self,
            _config: &Self::Config,
            _context: &mut Self::Context,
            _plan: RuntimePlan,
        ) -> nettrap_core::Result<()> {
            self.record("background");
            if self.fail_background {
                return Err(nettrap_core::Error::Runtime("background".into()));
            }
            Ok(())
        }

        async fn start_api(
            &mut self,
            _config: &Self::Config,
            _context: &mut Self::Context,
        ) -> nettrap_core::Result<()> {
            self.record("api");
            if self.fail_api {
                return Err(nettrap_core::Error::Runtime("api".into()));
            }
            Ok(())
        }

        async fn start_interceptor(
            &mut self,
            _config: &Self::Config,
            _context: &mut Self::Context,
        ) -> nettrap_core::Result<Option<Self::Interceptor>> {
            self.record("interceptor");
            if self.fail_interceptor {
                return Err(nettrap_core::Error::Runtime("interceptor".into()));
            }
            Ok(None)
        }

        async fn start_listeners(
            &mut self,
            _config: &Self::Config,
            _context: &Self::Context,
        ) -> nettrap_core::Result<Self::ListenerHandles> {
            self.record("listeners");
            if self.fail_listeners {
                return Err(nettrap_core::Error::Runtime("listeners".into()));
            }
            Ok(FakeListeners)
        }

        fn mark_startup_complete(
            &mut self,
            _context: &mut Self::Context,
            _listener_handles: &Self::ListenerHandles,
            _interceptor: Option<&Self::Interceptor>,
        ) {
            self.record("ready");
        }

        async fn shutdown_on_startup_error(
            &mut self,
            _config: &Self::Config,
            _context: &mut Self::Context,
            _listener_handles: Self::ListenerHandles,
            _interceptor: Option<Self::Interceptor>,
            error: nettrap_core::Error,
            phase: &'static str,
        ) -> nettrap_core::Result<()> {
            self.record(phase);
            self.record("shutdown_error");
            Err(error)
        }

        async fn wait_for_shutdown(
            &mut self,
            _stop_flag: Option<Self::StopFlag>,
        ) -> ShutdownReason {
            self.record("wait");
            ShutdownReason::StopFlag
        }

        async fn shutdown(
            &mut self,
            _config: &Self::Config,
            _context: &mut Self::Context,
            _listener_handles: Self::ListenerHandles,
            _interceptor: Option<Self::Interceptor>,
        ) -> Option<nettrap_core::Error> {
            self.record("shutdown");
            None
        }
    }

    #[tokio::test]
    async fn runtime_runner_executes_lifecycle_in_order() {
        let host = FakeHost {
            spawnable: true,
            ..FakeHost::default()
        };
        let events = Arc::clone(&host.events);

        RuntimeRunner::new(host, RuntimePlan::standard(false))
            .run(None)
            .await
            .unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "prepare",
                "initialize",
                "background",
                "api",
                "interceptor",
                "listeners",
                "ready",
                "wait",
                "shutdown"
            ]
        );
    }

    #[tokio::test]
    async fn runtime_runner_rejects_missing_spawnable_listener_before_initialization() {
        let host = FakeHost::default();
        let events = Arc::clone(&host.events);

        let error = RuntimeRunner::new(host, RuntimePlan::standard(false))
            .run(None)
            .await
            .expect_err("standard runtime should require a listener");

        assert!(error.to_string().contains("No spawnable listeners"));
        assert_eq!(*events.lock().unwrap(), vec!["prepare"]);
    }

    #[tokio::test]
    async fn runtime_runner_shuts_down_when_api_startup_fails() {
        let host = FakeHost {
            spawnable: true,
            fail_api: true,
            ..FakeHost::default()
        };
        let events = Arc::clone(&host.events);

        let error = RuntimeRunner::new(host, RuntimePlan::standard(false))
            .run(None)
            .await
            .expect_err("API startup should fail");

        assert!(matches!(
            error,
            nettrap_core::Error::Runtime(message) if message == "api"
        ));
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "prepare",
                "initialize",
                "background",
                "api",
                "API startup failure",
                "shutdown_error"
            ]
        );
    }
}
