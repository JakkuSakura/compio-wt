use std::sync::Arc;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("quic connection error: {0}")]
    Connection(#[from] compio_quic::ConnectionError),

    #[error("tls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("webtransport connect error: {0}")]
    Connect(#[from] web_transport_proto::ConnectError),

    #[error("webtransport settings error: {0}")]
    Settings(String),

    #[error("read error: {0}")]
    Read(String),

    #[error("write error: {0}")]
    Write(String),
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("quic connection error: {0}")]
    Connection(#[from] compio_quic::ConnectionError),

    #[error("tls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("webtransport connect error: {0}")]
    Connect(#[from] web_transport_proto::ConnectError),

    #[error("webtransport settings error: {0}")]
    Settings(String),

    #[error("read error: {0}")]
    Read(String),

    #[error("write error: {0}")]
    Write(String),
}

impl From<ServerError> for ClientError {
    fn from(e: ServerError) -> Self {
        match e {
            ServerError::Connection(e) => ClientError::Connection(e),
            ServerError::Rustls(e) => ClientError::Rustls(e),
            ServerError::Io(e) => ClientError::Io(e),
            ServerError::Connect(e) => ClientError::Connect(e),
            ServerError::Settings(e) => ClientError::Settings(e),
            ServerError::Read(e) => ClientError::Read(e),
            ServerError::Write(e) => ClientError::Write(e),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum SessionError {
    #[error("connection lost: {0}")]
    Connection(Arc<compio_quic::ConnectionError>),

    #[error("webtransport closed: code={0} reason={1}")]
    Closed(u32, String),

    #[error("read error: {0}")]
    Read(String),

    #[error("write error: {0}")]
    Write(String),
}

impl From<compio_quic::ConnectionError> for SessionError {
    fn from(e: compio_quic::ConnectionError) -> Self {
        Self::Connection(Arc::new(e))
    }
}
