use std::path::PathBuf;
use std::sync::Arc;

use super::StartupContext;
use crate::config::ListenerConfig;
use crate::listener_context::ListenerContext;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};

pub(crate) fn build_listener_context(
    listener: &ListenerConfig,
    startup: &StartupContext,
    smtp_dir_override: Option<PathBuf>,
) -> crate::Result<ListenerContext> {
    let smtp_dir = smtp_dir_override.or_else(|| {
        startup
            .output_path
            .as_ref()
            .map(|path| path.parent().unwrap_or(path).join("smtp"))
    });

    let process_filter = crate::process_filter::ProcessFilter::build(
        startup.global_process_whitelist.clone(),
        startup.global_process_blacklist.clone(),
        listener.process_whitelist.clone(),
        listener.process_blacklist.clone(),
    )?;

    let security = ListenerSecurity::new(
        process_filter.clone(),
        listener.host_whitelist.clone(),
        listener.host_blacklist.clone(),
    )?;

    let runtime = ListenerRuntime::new(ListenerRuntimeResources {
        ca: startup.ca.clone(),
        router: Arc::clone(&startup.router),
        attribution: startup.attribution.clone(),
        attribution_timeout: startup.attribution_timeout,
        pcap_writer: startup.pcap_writer.clone(),
        nbi_collector: Arc::clone(&startup.nbi_collector),
        session_tracker: Arc::clone(&startup.session_tracker),
        port_forward_table: Arc::clone(&startup.port_forward_table),
        flow_manager: Arc::clone(&startup.flow_manager),
    });

    ListenerContext::builder()
        .name(listener.name.clone())
        .port(listener.port)
        .banner(listener.banner.clone())
        .server_name(listener.server_name.clone())
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
        .dns_ncsi_response_ip(listener.dns_ncsi_response_ip.clone())
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
