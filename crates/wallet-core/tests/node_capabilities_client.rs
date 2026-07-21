use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use hacash_wallet_core::CapabilitySource;
use hacash_wallet_core::WalletError;
use hacash_wallet_core::node::NodeClient;

async fn spawn_status_node(status: StatusCode) -> (NodeClient, tokio::task::JoinHandle<()>) {
    let app = Router::new().route("/query/capabilities", get(move || async move { status }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock capability node");
    let address = listener.local_addr().expect("mock capability address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve mock capability node");
    });
    (
        NodeClient::new(format!("http://{address}")).expect("mock node client"),
        server,
    )
}

#[tokio::test]
async fn missing_capability_route_downgrades_to_explicit_legacy_type2() {
    let (node, server) = spawn_status_node(StatusCode::NOT_FOUND).await;
    let capabilities = node.capabilities().await.expect("legacy fallback");
    assert_eq!(capabilities.source, CapabilitySource::LegacyType2);
    assert_eq!(capabilities.transactions.enabled, vec![2]);
    assert!(!capabilities.istanbul.active);
    assert!(!capabilities.features.hvm);
    server.abort();
}

#[tokio::test]
async fn server_failure_never_downgrades_to_legacy() {
    let (node, server) = spawn_status_node(StatusCode::INTERNAL_SERVER_ERROR).await;
    let error = node.capabilities().await.expect_err("500 must fail");
    assert!(matches!(
        error,
        WalletError::NodeHttpStatus { status: 500, .. }
    ));
    server.abort();
}

#[tokio::test]
async fn invalid_success_json_never_downgrades_to_legacy() {
    let app = Router::new().route(
        "/query/capabilities",
        get(|| async { (StatusCode::OK, "not-json") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let node = NodeClient::new(format!("http://{address}")).unwrap();
    let error = node
        .capabilities()
        .await
        .expect_err("invalid JSON must fail");
    assert!(matches!(error, WalletError::Node(_)));
    server.abort();
}

#[tokio::test]
async fn declared_oversized_capability_response_is_rejected() {
    let app = Router::new().route(
        "/query/capabilities",
        get(|| async {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(vec![b'x'; 2 * 1024 * 1024 + 1]))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let node = NodeClient::new(format!("http://{address}")).unwrap();
    let error = node
        .capabilities()
        .await
        .expect_err("declared oversized body must fail before allocation");
    assert!(error.to_string().contains("exceeds 2097152 bytes"));
    server.abort();
}

#[tokio::test]
async fn chunked_oversized_capability_response_is_bounded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MAX: usize = 2 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: application/json\r\n\r\n")
            .await
            .unwrap();
        let chunk = vec![b'x'; CHUNK];
        for _ in 0..=(MAX / CHUNK) {
            if socket
                .write_all(format!("{CHUNK:X}\r\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            if socket.write_all(&chunk).await.is_err() || socket.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    let node = NodeClient::new(format!("http://{address}")).unwrap();
    let error = node
        .capabilities()
        .await
        .expect_err("chunked oversized body must stop at the local cap");
    assert!(error.to_string().contains("exceeds 2097152 bytes"));
    server.abort();
}
