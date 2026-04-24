// SMTP Protocol tests - cross-platform

#[cfg(test)]
mod tests {
    use nettrap_proto_smtp::handler::{SmtpHandler, SmtpHandlerTrait};

    #[tokio::test]
    async fn test_smtp_ehlo() {
        let handler = SmtpHandler::new();
        let result = handler.handle("EHLO test.example.com").await;
        assert!(result.is_ok(), "SMTP EHLO should succeed");

        let response = result.unwrap();
        assert!(response.message.contains("OK"), "EHLO should return OK");
        assert!(
            !response.message.contains("STARTTLS"),
            "EHLO should not advertise unsupported STARTTLS"
        );
    }

    #[tokio::test]
    async fn test_smtp_starttls_is_not_advertised_as_available() {
        let handler = SmtpHandler::new();
        let result = handler.handle("STARTTLS").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 454);
    }

    #[tokio::test]
    async fn test_smtp_mail_from() {
        let handler = SmtpHandler::new();
        let result = handler.handle("MAIL FROM: <test@example.com>").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 250);
    }

    #[tokio::test]
    async fn test_smtp_rcpt_to() {
        let handler = SmtpHandler::new();
        let result = handler.handle("RCPT TO: <user@example.com>").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 250);
    }

    #[tokio::test]
    async fn test_smtp_data() {
        let handler = SmtpHandler::new();
        let result = handler.handle("DATA").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 354);
    }

    #[tokio::test]
    async fn test_smtp_quit() {
        let handler = SmtpHandler::new();
        let result = handler.handle("QUIT").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 221);
    }

    #[tokio::test]
    async fn test_smtp_unknown_command() {
        let handler = SmtpHandler::new();
        let result = handler.handle("INVALID").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, 500);
    }

    #[test]
    fn test_smtp_banner() {
        let handler = SmtpHandler::new();
        let banner = handler.get_welcome_banner();
        assert!(
            banner.contains("nettrap.local"),
            "SMTP banner should contain domain"
        );
        assert!(banner.contains("ESMTP"), "SMTP banner should contain ESMTP");
        assert!(
            banner.contains("NetTrap"),
            "SMTP banner should contain NetTrap"
        );
    }

    #[test]
    fn test_smtp_domain() {
        let handler = SmtpHandler::new().with_domain("mail.example.com");
        assert_eq!(handler.domain(), "mail.example.com");
    }
}
