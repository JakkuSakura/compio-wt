//! WebTransport session — wraps a `compio_quic::Connection` after the CONNECT handshake.

use std::sync::Arc;

use compio_quic::{RecvStream, SendStream};

use crate::error::SessionError;

/// An established WebTransport session.
///
/// Wraps a `compio_quic::Connection` after the HTTP/3 CONNECT handshake has completed.
/// Provides access to bidirectional streams and datagrams.
#[derive(Clone)]
pub struct Session {
    conn: Arc<compio_quic::Connection>,
}

impl Session {
    pub fn new(conn: compio_quic::Connection) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }

    /// Accept an inbound bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        self.conn.accept_bi().await.map_err(SessionError::from)
    }

    /// Open a new outbound bidirectional stream.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        self.conn.open_bi().map_err(|e| {
            SessionError::Write(format!("open_bi: {e}"))
        })
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SessionError> {
        self.conn.send_datagram(data).map_err(|e| {
            SessionError::Write(format!("send_datagram: {e}"))
        })
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<bytes::Bytes, SessionError> {
        self.conn.recv_datagram().await.map_err(|e| {
            SessionError::Read(format!("recv_datagram: {e}"))
        })
    }

    /// Maximum datagram size.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Gracefully close the session.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    /// The underlying QUIC connection.
    pub fn conn(&self) -> &compio_quic::Connection {
        &self.conn
    }
}
