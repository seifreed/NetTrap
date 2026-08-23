use std::net::{IpAddr, SocketAddr};

use nettrap_core::Error;

use crate::handlers::ApiState;

fn validate_loopback_addr(addr: SocketAddr) -> crate::Result<()> {
    let is_loopback = match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |mapped| mapped.is_loopback()),
    };
    if !is_loopback {
        return Err(Error::Config(
            "API bind must use a loopback address because authentication is not available"
                .to_string(),
        ));
    }

    Ok(())
}

pub async fn run_server(addr: SocketAddr, state: ApiState) -> crate::Result<()> {
    validate_loopback_addr(addr)?;

    let router = crate::handlers::create_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(Error::Io)?;

    serve(listener, router).await
}

pub async fn serve(listener: tokio::net::TcpListener, router: axum::Router) -> crate::Result<()> {
    validate_loopback_addr(listener.local_addr().map_err(Error::Io)?)?;
    axum::serve(listener, router)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::ApiState;

    #[tokio::test]
    async fn test_run_server_non_loopback_bind_is_rejected() {
        let state = ApiState::new(std::sync::Arc::new(nettrap_flow::FlowManager::default()));
        let err = run_server("0.0.0.0:0".parse().expect("valid address"), state)
            .await
            .expect_err("unauthenticated API must not bind beyond loopback");

        assert!(err.to_string().contains("must use a loopback address"));
    }
}
