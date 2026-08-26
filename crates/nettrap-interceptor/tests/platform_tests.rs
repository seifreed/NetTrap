#![cfg(not(all(target_os = "windows", not(feature = "native-capture-tests"))))]

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    mod linux_tests {
        use nettrap_interceptor::InterceptorConfig;
        use nettrap_interceptor::platform::DefaultInterceptor;

        #[test]
        fn test_interceptor_creation() {
            let config = InterceptorConfig::default();
            let result = DefaultInterceptor::new(config);
            assert!(
                result.is_ok(),
                "Should be able to create default interceptor on Linux"
            );
        }

        #[test]
        fn test_pcap_creation() {
            let config = InterceptorConfig::default();
            let result = nettrap_interceptor::pcap::PcapInterceptor::new(config);
            assert!(
                result.is_ok(),
                "Should be able to create PCAP interceptor on Linux"
            );
        }
    }

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use nettrap_interceptor::InterceptorConfig;
        use nettrap_interceptor::platform::DefaultInterceptor;

        #[test]
        fn test_pcap_creation() {
            let config = InterceptorConfig::default();
            let result = nettrap_interceptor::pcap::PcapInterceptor::new(config);
            assert!(
                result.is_ok(),
                "Should be able to create PCAP interceptor on macOS"
            );
        }

        #[test]
        fn test_default_interceptor() {
            let config = InterceptorConfig::default();
            let result = DefaultInterceptor::new(config);
            assert!(
                result.is_ok(),
                "Should be able to create default interceptor on macOS"
            );
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        #[cfg(target_arch = "x86_64")]
        use nettrap_core::config::InterceptionMode;
        use nettrap_interceptor::InterceptorConfig;
        use nettrap_interceptor::platform::DefaultInterceptor;

        #[cfg(target_arch = "x86_64")]
        #[test]
        fn windivert_constructor_requires_windivert_mode() {
            let config = InterceptorConfig::default();
            assert!(DefaultInterceptor::new(config).is_err());

            let config = InterceptorConfig {
                mode: InterceptionMode::WinDivert,
                ..Default::default()
            };
            assert!(DefaultInterceptor::new(config).is_ok());
        }

        #[cfg(target_arch = "aarch64")]
        #[test]
        fn arm64_default_interceptor_uses_pcap_without_opening_device() {
            let config = InterceptorConfig {
                interface: Some("Npcap test interface".to_string()),
                ..Default::default()
            };
            assert!(DefaultInterceptor::new(config).is_ok());
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    mod other_tests {
        use nettrap_interceptor::InterceptorConfig;

        #[test]
        fn test_pcap_fallback() {
            let config = InterceptorConfig::default();
            let result = nettrap_interceptor::pcap::PcapInterceptor::new(config);
            assert!(result.is_ok(), "PCAP should be available as fallback");
        }
    }
}
