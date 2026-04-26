// FTP Protocol tests - cross-platform

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
    fn test_ftp_unknown_command() {
        let handler = FtpHandler::new();
        let response = handler.handle("INVALID");
        assert_eq!(response.code, 502);
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
        let handler = FtpHandler::new().with_banner("220 Custom FTP Server");
        let banner = handler.get_banner();
        assert!(
            banner.starts_with(b"220"),
            "Custom banner should start with 220"
        );
    }
}
