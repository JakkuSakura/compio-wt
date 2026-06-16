//! WebTransport client — connects to a WebTransport server over compio_quic.

use std::sync::Arc;
use std::time::Duration;

use compio_quic::ClientBuilder;

use crate::connect::client_connect;
use crate::error::ClientError;
use crate::session::Session;

/// Connect to a WebTransport server at the given URL.
///
/// `url` must have `https` scheme — the host and port are used for the QUIC
/// connection, and the full URL path is sent in the CONNECT request.
///
/// Uses platform default certificate verification (webpki roots).
pub async fn connect(
    url: &url::Url,
    server_addr: std::net::SocketAddr,
) -> Result<Session, ClientError> {
    connect_with_client_config(url, server_addr, None, false).await
}

/// Connect with optional custom TLS configuration.
pub async fn connect_with_client_config(
    url: &url::Url,
    server_addr: std::net::SocketAddr,
    tls_config: Option<compio_quic::ClientConfig>,
    insecure_skip_verify: bool,
) -> Result<Session, ClientError> {
    let builder = if insecure_skip_verify {
        ClientBuilder::new_with_no_server_verification()
    } else {
        ClientBuilder::new_with_webpki_roots().with_no_crls()
    };
    let mut transport = compio_quic::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(1)));
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport.initial_mtu(1200);
    let mut client_config = if let Some(cfg) = tls_config {
        cfg
    } else {
        builder
            .with_alpn_protocols(&[crate::ALPN])
            .build()
    };
    client_config.transport_config(Arc::new(transport));

    let bind_addr: std::net::SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = compio_quic::Endpoint::client(bind_addr)
        .await
        .map_err(|e| ClientError::Io(e))?;
    endpoint.default_client_config = Some(client_config);

    let server_name = url
        .host_str()
        .unwrap_or("localhost")
        .to_string();

    let connecting = endpoint
        .connect(server_addr, &server_name, None)
        .map_err(|e| ClientError::Read(format!("connect: {e}")))?;
    let conn = connecting
        .await
        .map_err(|e| ClientError::Connection(e))?;

    let (send, recv) = conn
        .open_bi()
        .map_err(|e| ClientError::Write(format!("open_bi: {e}")))?;

    let (_request, _response) = client_connect(&conn, send, recv, url).await?;

    Ok(Session::new(conn))
}
