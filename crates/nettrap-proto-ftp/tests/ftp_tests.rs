#[cfg(test)]
mod tests {
    use nettrap_proto_ftp::ftp::FtpHandler;

    #[test]
    fn test_ftp_user() {
        let handler = FtpHandler::new();
        let response = handler.handle("USER test");
        assert_eq!(response.code, 331);
        assert!(response.message.contains("password"));
    }

    #[test]
    fn test_ftp_pass() {
        let handler = FtpHandler::new();
        let response = handler.handle("PASS password");
        assert_eq!(response.code, 230);
    }

    #[test]
    fn test_ftp_pwd() {
        let handler = FtpHandler::new();
        let response = handler.handle("PWD");
        assert_eq!(response.code, 257);
    }

    #[test]
    fn test_ftp_quit() {
        let handler = FtpHandler::new();
        let response = handler.handle("QUIT");
        assert_eq!(response.code, 221);
    }

    #[test]
    fn test_ftp_type() {
        let handler = FtpHandler::new();
        let response = handler.handle("TYPE I");
        assert_eq!(response.code, 200);
    }

    #[test]
    fn test_ftp_pasv() {
        let handler = FtpHandler::new();
        let response = handler.handle("PASV");
        assert_eq!(response.code, 227);
    }

    #[test]
    fn test_ftp_feat_advertises_rest_stream() {
        let handler = FtpHandler::new();
        let response = handler.handle("FEAT");
        let text = String::from_utf8(response.to_bytes()).expect("FEAT response should be UTF-8");

        assert!(text.starts_with("211-Features:\r\n"));
        assert!(text.contains("\r\n REST STREAM\r\n"));
        assert!(text.contains("\r\n HOST\r\n"));
        assert!(text.ends_with("211 End\r\n"));
    }

    #[test]
    fn test_ftp_host_accepts_domain_names() {
        let handler = FtpHandler::new();

        let domain = handler.handle("HOST ftp.example.com");
        assert_eq!(domain.code, 220);
    }

    #[test]
    fn test_ftp_host_rejects_invalid_targets() {
        let handler = FtpHandler::new();

        assert_eq!(handler.handle("HOST").code, 501);
        assert_eq!(handler.handle("HOST bad host").code, 501);
        assert_eq!(handler.handle("HOST 999.999.999.999").code, 501);
        assert_eq!(handler.handle("HOST 192.0.2.10").code, 504);
        assert_eq!(handler.handle("HOST [2001:db8::1]").code, 504);
    }

    #[test]
    fn test_ftp_list() {
        let handler = FtpHandler::new();
        let response = handler.handle("LIST");
        assert_eq!(response.code, 425);

        let transfer = handler
            .prepare_data_transfer("LIST")
            .expect("list transfer should be prepared");
        assert_eq!(transfer.start_response.code, 150);
        assert!(String::from_utf8_lossy(&transfer.data).contains("index.html"));
        assert_eq!(transfer.complete_response.code, 226);
    }

    #[test]
    fn test_ftp_retr() {
        let handler = FtpHandler::new();
        let response = handler.handle("RETR file.txt");
        assert_eq!(response.code, 425);

        let transfer = handler
            .prepare_data_transfer("RETR file.txt")
            .expect("retr transfer should be prepared");
        assert_eq!(transfer.start_response.code, 150);
        assert_eq!(transfer.complete_response.code, 226);
    }

    #[test]
    fn test_ftp_retr_uses_default_content_without_root() {
        let handler = FtpHandler::new();
        let transfer = handler
            .prepare_data_transfer("RETR payload.exe")
            .expect("retr transfer should be prepared");

        assert_eq!(transfer.start_response.code, 150);
        assert_eq!(transfer.complete_response.code, 226);
        assert!(transfer.data.starts_with(b"MZ"));
        assert_eq!(transfer.data.len(), 256);
    }

    #[test]
    fn test_ftp_retr_without_root_rejects_unknown_extension() {
        let handler = FtpHandler::new();
        let err = handler
            .prepare_data_transfer("RETR payload.unknown")
            .expect_err("unknown extension should be rejected");

        assert_eq!(err.code, 550);
    }

    #[test]
    fn test_ftp_unknown_command() {
        let handler = FtpHandler::new();
        let response = handler.handle("INVALID");
        assert_eq!(response.code, 502);
    }

    #[test]
    fn test_ftp_help_lists_supported_commands() {
        let handler = FtpHandler::new();
        let response = handler.handle("HELP");
        let text = String::from_utf8(response.to_bytes()).expect("HELP response should be UTF-8");

        assert!(text.starts_with("214-The following commands are recognized:\r\n"));
        for command in ["HOST", "PORT", "EPRT", "REST", "STOR", "ABOR", "FEAT"] {
            assert!(
                text.contains(command),
                "HELP output should mention {command}"
            );
        }
        assert!(text.ends_with("214 Help OK.\r\n"));
    }

    #[test]
    fn test_ftp_banner() {
        let handler = FtpHandler::new();
        let banner = handler.get_banner();
        assert!(
            banner.starts_with(b"220"),
            "FTP banner should start with 220"
        );
    }

    #[test]
    fn test_ftp_custom_banner() {
        let handler = FtpHandler::new()
            .with_preformatted_banner("220 Custom FTP Server")
            .expect("valid FTP banner");
        let banner = handler.get_banner();
        assert!(
            banner.starts_with(b"220"),
            "Custom banner should start with 220"
        );
    }
}
