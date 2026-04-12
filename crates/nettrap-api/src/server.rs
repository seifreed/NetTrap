use crate::handlers::ApiState;
use nettrap_core::Error;

pub async fn run_server(addr: std::net::SocketAddr, state: ApiState) -> crate::Result<()> {
    let router = crate::handlers::create_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(Error::Io)?;

    serve(listener, router).await
}

pub async fn serve(listener: tokio::net::TcpListener, router: axum::Router) -> crate::Result<()> {
    axum::serve(listener, router)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?;

    Ok(())
}
