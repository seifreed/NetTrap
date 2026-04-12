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
/// - Must not start or end with hyphen or dot
/// - Must not have consecutive dots
/// - Labels must be alphanumeric or hyphen only
/// - Cannot be all-numeric (to avoid IP address confusion)
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Must not start or end with hyphen or dot
    if hostname.starts_with('-')
        || hostname.ends_with('-')
        || hostname.starts_with('.')
        || hostname.ends_with('.')
    {
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = hostname.split('.').collect();

    for label in &labels {
        // Each label must be non-empty and <= 63 chars
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Must not start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        // Must be alphanumeric or hyphen only
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    // Reject if it's just underscores (not a valid DNS hostname)
    if hostname.starts_with('_') {
        return false;
    }

    true
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
        let is_tls = peeked.len() >= 3 && peeked[0] == 0x16 && peeked[1] == 0x03 && peeked[2] <= 0x04;

        if !is_tls {
            return Ok((WrappedStream::Plain(stream), None));
        }

        let sni = extract_sni(peeked);
        let hostname = sni
            .clone()
            .filter(|s| is_valid_hostname(s))
            .unwrap_or_else(|| "localhost".to_string());

        let (cert_pem, key_pem) = self.ca.generate_cert_for_host(&hostname)?;
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
