use crate::config::EngineConfig;

pub fn init_windows_network(config: &EngineConfig) {
    if cfg!(target_os = "windows") {
        if config.has_debug_flag("FIXGATEWAY") {
            crate::windows_setup::fix_gateway();
        }
        if should_modify_local_dns(config) {
            crate::windows_setup::fix_dns(config.restrict_interface.as_deref());
            crate::windows_setup::flush_dns(config.dns_flush_command.as_deref());
        }
        if config.has_debug_flag("STOPDNSSERVICE") {
            crate::windows_setup::stop_dns_service();
        }
    }
}

pub(crate) fn should_modify_local_dns(config: &EngineConfig) -> bool {
    config.modify_local_dns || config.has_debug_flag("FIXDNS")
}

pub fn init_windows_ca_trust(config: &EngineConfig) -> Option<String> {
    let dir = config.tls_cert_dir.as_ref()?;

    let cert_path = tls_ca_cert_path(dir);
    crate::windows_setup::install_ca_trust(cert_path)
}

pub(crate) fn tls_ca_cert_path(dir: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    dir.as_ref().join("ca.crt")
}
