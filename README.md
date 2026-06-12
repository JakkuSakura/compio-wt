# compio-wt

WebTransport server for [compio-quic](https://github.com/compio-rs/compio).

Handles the HTTP/3 SETTINGS exchange and WebTransport CONNECT handshake over `compio_quic`, yielding a `Session` that exposes bidirectional streams and datagrams — same API as raw QUIC.

Adapted from [`web-transport-quinn`](https://github.com/moq-dev/web-transport).

## Usage

```rust
use compio_wt::{Server, ALPN};

let mut server = Server::build(
    "0.0.0.0:4433".parse().unwrap(),
    cert_chain,
    key_der,
).await?;

while let Some(session) = server.accept().await? {
    // session: Session — works like compio_quic::Connection
    let (send, recv) = session.accept_bi().await?;
    // send/receive WebTransport frames
}
```

## How it works

1. QUIC listener with ALPN `"h3"` (HTTP/3)
2. For each incoming connection:
   - Reads peer SETTINGS from unidirectional control stream
   - Writes our SETTINGS (WebTransport enabled)
   - Reads HTTP/3 HEADERS frame with `:method = CONNECT`, `:protocol = webtransport`
   - Responds `200 OK`
3. Returns a `Session` — the bidirectional stream is now free for application data

## License

MIT OR Apache-2.0
