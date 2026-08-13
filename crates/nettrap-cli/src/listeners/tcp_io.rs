use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::listener_context::ListenerContext;

use super::MAX_TLS_RECORD_SIZE;

pub(crate) async fn read_tcp_with_timeout<R>(
    ctx: &ListenerContext,
    stream: &mut R,
    buf: &mut [u8],
    peer: &SocketAddr,
    label: &str,
) -> Option<usize>
where
    R: AsyncRead + Unpin,
{
    let timeout = Duration::from_millis(ctx.timeout_ms());
    match tokio::time::timeout(timeout, stream.read(buf)).await {
        Ok(Ok(0)) => {
            tracing::debug!("{} connection closed by {}", label, peer);
            None
        }
        Ok(Ok(len)) => Some(len),
        Ok(Err(e)) => {
            tracing::debug!("{} read error from {}: {}", label, peer, e);
            None
        }
        Err(_) => {
            tracing::debug!(
                "{} '{}' read timed out after {} ms from {}",
                label,
                ctx.name(),
                ctx.timeout_ms(),
                peer
            );
            None
        }
    }
}

pub(crate) async fn write_tcp_with_timeout<W>(
    ctx: &ListenerContext,
    stream: &mut W,
    data: &[u8],
    peer: &SocketAddr,
    label: &str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let timeout = Duration::from_millis(ctx.timeout_ms());
    match tokio::time::timeout(timeout, async {
        stream.write_all(data).await?;
        stream.flush().await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::debug!(
                "{} '{}' write timed out after {} ms to {}",
                label,
                ctx.name(),
                ctx.timeout_ms(),
                peer
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} '{}' write timed out after {} ms to {}",
                    label,
                    ctx.name(),
                    ctx.timeout_ms(),
                    peer
                ),
            ))
        }
    }
}

pub(crate) fn tls_record_total_len(header: &[u8]) -> Option<usize> {
    if header.len() < 5 || header[0] != 0x16 || header[1] != 0x03 || header[2] > 0x04 {
        return None;
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = 5usize.checked_add(record_len)?;
    if total_len > MAX_TLS_RECORD_SIZE {
        return None;
    }

    Some(total_len)
}

pub(crate) async fn peek_until_len(
    stream: &tokio::net::TcpStream,
    buf: &mut [u8],
    min_len: usize,
    timeout: Duration,
) -> std::io::Result<usize> {
    match tokio::time::timeout(timeout, async {
        loop {
            let len = stream.peek(buf).await?;
            if len == 0 || len >= min_len {
                return Ok(len);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TLS ClientHello peek timed out",
        )),
    }
}

pub(crate) async fn peek_complete_tls_record(
    stream: &tokio::net::TcpStream,
    timeout: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 3];
    let prefix_min_len = prefix.len();
    let prefix_len = peek_until_len(stream, &mut prefix, prefix_min_len, timeout).await?;
    if prefix_len < prefix_min_len || prefix[0] != 0x16 || prefix[1] != 0x03 || prefix[2] > 0x04 {
        return Ok(None);
    }

    let mut header = [0u8; 5];
    let header_min_len = header.len();
    let header_len = peek_until_len(stream, &mut header, header_min_len, timeout).await?;
    if header_len < header_min_len {
        return Ok(None);
    }

    let Some(total_len) = tls_record_total_len(&header) else {
        return Ok(None);
    };

    let mut record = vec![0u8; total_len];
    let peeked_len = peek_until_len(stream, &mut record, total_len, timeout).await?;
    if peeked_len < total_len {
        return Ok(None);
    }

    Ok(Some(record))
}
