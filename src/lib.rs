//! WebTransport for compio-quic.
//!
//! Vendored fork of [`web-transport-quinn`](https://github.com/moq-dev/web-transport) adapted for
//! `compio_quic` instead of `quinn`. Provides HTTP/3 WebTransport CONNECT handshake over a
//! compio_quic endpoint, yielding a [`Session`] that exposes bidirectional streams and datagrams.

mod connect;
mod error;
mod server;
mod session;

pub use error::*;
pub use server::*;
pub use session::*;

/// The HTTP/3 ALPN required for WebTransport.
pub const ALPN: &str = "h3";

/// Re-export compio_quic since it's in the public API.
pub use compio_quic;
