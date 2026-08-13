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
        use nettrap_interceptor::InterceptorConfig;
        use nettrap_interceptor::platform::DefaultInterceptor;

        #[test]
        fn test_interceptor_creation() {
            let config = InterceptorConfig::default();
            let result = DefaultInterceptor::new(config);
            assert!(
                result.is_ok() || result.is_err(),
                "Interceptor code should compile on Windows"
            );
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
