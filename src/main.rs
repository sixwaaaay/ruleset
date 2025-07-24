use axum::{Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gzip compression layer
    let compression_layer = tower_http::compression::CompressionLayer::new();

    let app = Router::new()
        .route(
            "/greet",
            get(|| async { "Hello, This is a long text to compress with gzip algorithm!" }),
        )
        .layer(compression_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3500));
    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;
    Ok(())
}
