//! WebTransport server — adapted from [`web-transport-quinn`] for `compio_quic`.

use std::sync::Arc;

use compio_quic::ServerBuilder as QuicServerBuilder;

use crate::connect::server_accept;
use crate::error::ServerError;
use crate::session::Session;

/// WebTransport server that accepts WebTransport sessions.
pub struct Server {
    endpoint: Arc<compio_quic::Endpoint>,
}

impl Server {
    /// Create a new WebTransport server from an existing compio_quic endpoint.
    /// The endpoint must be configured with ALPN = [`crate::ALPN`] ("h3").
    pub fn new(endpoint: compio_quic::Endpoint) -> Self {
        Self {
            endpoint: Arc::new(endpoint),
        }
    }

    /// Accept a new WebTransport session.
    ///
    /// Returns `None` when the endpoint is closed.
    pub async fn accept(&self) -> Result<Option<Session>, ServerError> {
        let Some(incoming) = self.endpoint.wait_incoming().await else {
            return Ok(None);
        };
        let conn = incoming.await.map_err(ServerError::from)?;
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| ServerError::Read(e.to_string()))?;

        let (_request, _response) = server_accept(&conn, send, recv).await?;

        Ok(Some(Session::new(conn)))
    }

    /// Convenience: build a server with the given certificate, key, and bind address.
    pub async fn build(
        bind_addr: std::net::SocketAddr,
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Self, ServerError> {
        let server_config = QuicServerBuilder::new_with_single_cert(cert_chain, key_der)
            .map_err(ServerError::from)?
            .with_alpn_protocols(&[crate::ALPN])
            .build();

        let endpoint = compio_quic::Endpoint::server(bind_addr, server_config)
            .await
            .map_err(ServerError::from)?;

        Ok(Self::new(endpoint))
    }
}
