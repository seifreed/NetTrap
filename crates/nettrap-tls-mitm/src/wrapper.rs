use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use nettrap_core::error::{Error, Result};

use crate::ca::CertificateAuthority;
use crate::cert::{build_server_config, extract_sni};

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
        let is_tls = peeked.len() >= 3 && peeked[0] == 0x16 && peeked[1] == 0x03;

        if !is_tls {
            return Ok((WrappedStream::Plain(stream), None));
        }

        let sni = extract_sni(peeked);
        let hostname = sni.clone().unwrap_or_else(|| "localhost".to_string());

        let (cert_pem, key_pem) = self.ca.generate_cert_for_host(&hostname)?;
        let config = build_server_config(&cert_pem, &key_pem, self.ca.ca_cert_pem())?;
        let acceptor = TlsAcceptor::from(config);

        let tls_stream = acceptor.accept(stream).await
            .map_err(|e| Error::Tls(format!("TLS handshake failed for {}: {}", hostname, e)))?;

        tracing::debug!("TLS handshake completed for {}", hostname);
        Ok((WrappedStream::Tls(tls_stream), sni))
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

        acceptor.accept(stream).await
            .map_err(|e| Error::Tls(format!("TLS handshake failed for {}: {}", hostname, e)))
    }
}

/// A TCP stream that may or may not be TLS-wrapped
pub enum WrappedStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
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
