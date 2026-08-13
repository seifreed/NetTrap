use nettrap_core::error::{Error, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::ca::CertificateAuthority;
use crate::cert::{build_server_config, extract_sni};

/// Validate a hostname according to RFC 1123 (DNS) rules.
/// - Must not be empty
/// - Must not exceed 253 characters  
/// - Must not start with hyphen or dot
/// - Absolute hostnames may end with a single dot
/// - Must not have consecutive dots
/// - Labels must be alphanumeric or hyphen only
/// - Cannot be all-numeric because TLS SNI host_name carries DNS names, not IP literals
fn is_valid_hostname(hostname: &str) -> bool {
    // Absolute hostnames may carry a single trailing dot.
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    if hostname.starts_with('-') || hostname.ends_with('-') || hostname.starts_with('.') {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    // Reject if it's just underscores (not a valid DNS hostname)
    if hostname.starts_with('_') {
        return false;
    }

    // Reject all-numeric hostnames to avoid IP address confusion (RFC 1123).
    if labels
        .iter()
        .all(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }

    true
}

fn is_valid_certificate_subject(subject: &str) -> bool {
    match subject.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none_or(|mapped| {
                    !mapped.is_unspecified() && !mapped.is_multicast() && !mapped.is_broadcast()
                })
        }
        Err(_) => is_valid_hostname(subject),
    }
}

/// Wraps a TCP stream with TLS if a ClientHello is detected
pub struct TlsWrapper {
    ca: Arc<CertificateAuthority>,
}

impl TlsWrapper {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca }
    }

    /// Peek at the stream to detect TLS, then wrap if needed.
    /// Returns either a plain stream or a TLS stream, plus the peeked data and optional SNI.
    pub async fn maybe_wrap(
        &self,
        stream: TcpStream,
        peeked: &[u8],
    ) -> Result<(WrappedStream, Option<String>)> {
        let is_tls =
            peeked.len() >= 3 && peeked[0] == 0x16 && peeked[1] == 0x03 && peeked[2] <= 0x04;

        if !is_tls {
            return Ok((WrappedStream::Plain(stream), None));
        }

        let sni = extract_sni(peeked);
        let Some(hostname) = sni.as_ref().filter(|s| is_valid_hostname(s)) else {
            return Err(Error::Tls(
                "Invalid or missing SNI in TLS ClientHello".to_string(),
            ));
        };

        let (cert_pem, key_pem) = self.ca.generate_cert_for_host(hostname)?;
        let config = build_server_config(&cert_pem, &key_pem, self.ca.ca_cert_pem())?;
        let acceptor = TlsAcceptor::from(config);

        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed for {}: {}", hostname, e)))?;

        tracing::debug!("TLS handshake completed for {}", hostname);
        Ok((WrappedStream::Tls(Box::new(tls_stream)), sni))
    }

    /// Force TLS wrapping with a specific hostname
    pub async fn wrap_with_hostname(
        &self,
        stream: TcpStream,
        hostname: &str,
    ) -> Result<TlsStream<TcpStream>> {
        if !is_valid_certificate_subject(hostname) {
            return Err(Error::Tls("invalid certificate hostname".to_string()));
        }

        let (cert_pem, key_pem) = self.ca.generate_cert_for_host(hostname)?;
        let config = build_server_config(&cert_pem, &key_pem, self.ca.ca_cert_pem())?;
        let acceptor = TlsAcceptor::from(config);

        acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed for {}: {}", hostname, e)))
    }
}

/// A TCP stream that may or may not be TLS-wrapped
pub enum WrappedStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl WrappedStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, WrappedStream::Tls(_))
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WrappedStream::Plain(s) => s.read(buf).await,
            WrappedStream::Tls(s) => s.read(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            WrappedStream::Plain(s) => s.write_all(buf).await,
            WrappedStream::Tls(s) => s.write_all(buf).await,
        }
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WrappedStream::Plain(s) => s.flush().await,
            WrappedStream::Tls(s) => s.flush().await,
        }
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            WrappedStream::Plain(s) => s.shutdown().await,
            WrappedStream::Tls(s) => s.shutdown().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TlsWrapper, is_valid_certificate_subject, is_valid_hostname};
    use crate::ca::CertificateAuthority;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn accepts_normal_hostnames() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.co.uk"));
        assert!(is_valid_hostname("localhost"));
        assert!(is_valid_hostname("a1.example.com"));
        assert!(is_valid_hostname("1host.example.com"));
        assert!(is_valid_hostname("example.com."));
    }

    #[test]
    fn accepts_absolute_hostnames_at_length_limit() {
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );

        assert_eq!(hostname.len(), 254);
        assert!(is_valid_hostname(&hostname));
    }

    #[test]
    fn rejects_all_numeric_hostnames() {
        // IPv4 literals must not be accepted as SNI hostnames (RFC 1123).
        assert!(!is_valid_hostname("127.0.0.1"));
        assert!(!is_valid_hostname("10.0.0.255"));
        assert!(!is_valid_hostname("8.8.8.8"));
        assert!(!is_valid_hostname("12345"));
    }

    #[test]
    fn accepts_ip_literal_certificate_subjects() {
        assert!(is_valid_certificate_subject("127.0.0.1"));
        assert!(is_valid_certificate_subject("::1"));
        assert!(is_valid_certificate_subject("example.com"));
    }

    #[test]
    fn rejects_unspecified_ip_literal_certificate_subjects() {
        assert!(!is_valid_certificate_subject("0.0.0.0"));
        assert!(!is_valid_certificate_subject("::"));
        assert!(!is_valid_certificate_subject("::ffff:0.0.0.0"));
    }

    #[test]
    fn rejects_multicast_and_broadcast_ip_literal_certificate_subjects() {
        for subject in [
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            assert!(
                !is_valid_certificate_subject(subject),
                "subject should be rejected: {subject}"
            );
        }
    }

    #[test]
    fn rejects_malformed_hostnames() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-bad.example.com"));
        assert!(!is_valid_hostname("bad-.example.com"));
        assert!(!is_valid_hostname(".example.com"));
        assert!(!is_valid_hostname("example..com"));
        assert!(!is_valid_hostname("_dmarc.example.com"));
    }

    fn client_hello_without_sni() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());

        let handshake_len = body.len();
        let mut record_body = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        record_body.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(record_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&record_body);
        record
    }

    fn client_hello_with_sni(hostname: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();
        let sni_ext_len = 2 + 1 + 2 + hostname.len();
        extension.extend_from_slice(&0x0000u16.to_be_bytes());
        extension.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extension.extend_from_slice(&((1 + 2 + hostname.len()) as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extension.extend_from_slice(hostname);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);

        let handshake_len = body.len();
        let mut record_body = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        record_body.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(record_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&record_body);
        record
    }

    async fn connected_tcp_stream() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener should have address");
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await.expect("accept should succeed");
        });
        let stream = TcpStream::connect(addr)
            .await
            .expect("test stream should connect");
        let _ = accept.await;
        stream
    }

    #[tokio::test]
    async fn maybe_wrap_rejects_missing_or_invalid_sni_at_tls_boundary() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));

        let missing_sni = client_hello_without_sni();
        let stream = connected_tcp_stream().await;
        let err = match wrapper.maybe_wrap(stream, &missing_sni).await {
            Ok(_) => panic!("missing SNI should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("Invalid or missing SNI"));

        let invalid_sni = client_hello_with_sni(b"127.0.0.1");
        let stream = connected_tcp_stream().await;
        let err = match wrapper.maybe_wrap(stream, &invalid_sni).await {
            Ok(_) => panic!("invalid SNI should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("Invalid or missing SNI"));
    }

    #[tokio::test]
    async fn maybe_wrap_accepts_absolute_hostnames_in_sni() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));

        let trailing_dot_sni = client_hello_with_sni(b"example.test.");
        let stream = connected_tcp_stream().await;
        let err = match wrapper.maybe_wrap(stream, &trailing_dot_sni).await {
            Ok(_) => panic!("peer without TLS client completion should fail the handshake"),
            Err(err) => err,
        };

        let err = err.to_string();
        assert!(!err.contains("Invalid or missing SNI"));
        assert!(err.contains("TLS handshake failed"));
    }

    #[tokio::test]
    async fn wrap_with_hostname_rejects_invalid_hostnames() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));

        for hostname in ["_bad.example", "0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let stream = connected_tcp_stream().await;
            let err = match wrapper.wrap_with_hostname(stream, hostname).await {
                Ok(_) => panic!("invalid hostname should be rejected"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains("invalid certificate hostname"),
                "unexpected error for {hostname}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn wrap_with_hostname_accepts_absolute_hostnames_at_length_limit() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );

        let stream = connected_tcp_stream().await;
        let err = match wrapper.wrap_with_hostname(stream, &hostname).await {
            Ok(_) => panic!("peer without TLS client hello should fail the handshake"),
            Err(err) => err,
        };

        assert!(!err.to_string().contains("invalid certificate hostname"));
        assert!(err.to_string().contains("TLS handshake failed"));
    }

    #[tokio::test]
    async fn wrap_with_hostname_accepts_absolute_hostnames_before_handshake() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));

        let stream = connected_tcp_stream().await;
        let err = match wrapper.wrap_with_hostname(stream, "example.test.").await {
            Ok(_) => panic!("peer without TLS client hello should fail the handshake"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("TLS handshake failed for example.test")
        );
    }

    #[tokio::test]
    async fn wrap_with_hostname_accepts_ip_literal_before_handshake() {
        let wrapper = TlsWrapper::new(Arc::new(
            CertificateAuthority::generate().expect("CA should generate"),
        ));

        let stream = connected_tcp_stream().await;
        let err = match wrapper.wrap_with_hostname(stream, "127.0.0.1").await {
            Ok(_) => panic!("peer without TLS client hello should fail the handshake"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("TLS handshake failed for 127.0.0.1")
        );
    }
}
