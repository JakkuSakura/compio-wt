//! HTTP/3 SETTINGS exchange and WebTransport CONNECT handshake.

use bytes::BytesMut;
use web_transport_proto::{
    ConnectRequest, ConnectResponse, Frame, Settings, StreamUni, VarInt,
};

use crate::error::{ClientError, ServerError};

// ── Server-side ─────────────────────────────────────────────────

/// Perform the server-side HTTP/3 SETTINGS exchange and CONNECT handshake.
pub async fn server_accept(
    conn: &compio_quic::Connection,
    mut send: compio_quic::SendStream,
    mut recv: compio_quic::RecvStream,
) -> Result<(ConnectRequest, ConnectResponse), ServerError> {
    // 1. Accept peer's unidirectional control stream → read SETTINGS
    let mut control_recv = conn.accept_uni().await.map_err(ServerError::from)?;
    let settings = read_settings(&mut control_recv).await
        .map_err(|e| ServerError::Settings(e))?;
    if settings.supports_webtransport() == 0 {
        return Err(ServerError::Settings("peer does not support WebTransport".into()));
    }

    // 2. Open our control stream → write SETTINGS with WebTransport enabled
    let mut control_send = conn.open_uni().map_err(|e| ServerError::Write(e.to_string()))?;
    let mut our_settings = Settings::default();
    our_settings.enable_webtransport(1);
    write_settings(&mut control_send, &our_settings).await
        .map_err(|e| ServerError::Write(e))?;

    // 3. Read CONNECT request from the bidirectional stream
    let request = read_connect_request(&mut recv).await?;

    // 4. Write 200 OK
    let response = ConnectResponse::OK;
    write_connect_response(&mut send, &response).await?;

    Ok((request, response))
}

// ── Client-side ─────────────────────────────────────────────────

/// Perform the client-side HTTP/3 SETTINGS exchange and CONNECT handshake.
pub async fn client_connect(
    conn: &compio_quic::Connection,
    mut send: compio_quic::SendStream,
    mut recv: compio_quic::RecvStream,
    url: &url::Url,
) -> Result<(ConnectRequest, ConnectResponse), ClientError> {
    // 1. Open our control stream → write SETTINGS with WebTransport enabled
    let mut control_send = conn.open_uni().map_err(|e| ClientError::Write(e.to_string()))?;
    let mut our_settings = Settings::default();
    our_settings.enable_webtransport(1);
    write_settings(&mut control_send, &our_settings).await
        .map_err(|e| ClientError::Write(e))?;

    // 2. Read server's control stream → read SETTINGS
    let mut control_recv = conn.accept_uni().await.map_err(ClientError::Connection)?;
    let settings = read_settings(&mut control_recv).await
        .map_err(|e| ClientError::Settings(e))?;
    if settings.supports_webtransport() == 0 {
        return Err(ClientError::Settings("server does not support WebTransport".into()));
    }

    // 3. Write CONNECT request on the bidirectional stream
    let request = ConnectRequest::new(url.clone());
    write_connect_request(&mut send, &request).await
        .map_err(|e| ClientError::Write(e))?;

    // 4. Read 200 OK
    let response = read_connect_response(&mut recv).await
        .map_err(|e| ClientError::Read(e))?;

    Ok((request, response))
}

// ── Frame I/O (internal, use String errors) ────────────────────

async fn read_frame(recv: &mut compio_quic::RecvStream) -> Result<(VarInt, Vec<u8>), String> {
    let typ = read_varint(recv).await?;
    let len = read_varint(recv).await?;
    let mut payload = vec![0u8; len.into_inner() as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| format!("frame payload: {e}"))?;
    Ok((typ, payload))
}

async fn write_frame(
    send: &mut compio_quic::SendStream,
    typ: VarInt,
    payload: &[u8],
) -> Result<(), String> {
    let typ_enc = encode_varint(typ);
    let len_enc = encode_varint(VarInt::from_u32(payload.len() as u32));
    send.write_all(&typ_enc).await.map_err(|e| format!("frame type: {e}"))?;
    send.write_all(&len_enc).await.map_err(|e| format!("frame len: {e}"))?;
    send.write_all(payload).await.map_err(|e| format!("frame payload: {e}"))?;
    Ok(())
}

// ── Settings ───────────────────────────────────────────────────

async fn read_settings(recv: &mut compio_quic::RecvStream) -> Result<Settings, String> {
    let st = read_varint(recv).await?;
    if st != StreamUni::CONTROL.0 {
        return Err("expected CONTROL stream".into());
    }
    let (typ, payload) = read_frame(recv).await?;
    if typ != Frame::SETTINGS.0 {
        return Err("expected SETTINGS frame".into());
    }
    Settings::decode(&mut &payload[..]).map_err(|e| e.to_string())
}

async fn write_settings(
    send: &mut compio_quic::SendStream,
    settings: &Settings,
) -> Result<(), String> {
    let st = encode_varint(StreamUni::CONTROL.0);
    send.write_all(&st).await.map_err(|e| e.to_string())?;
    let mut buf = BytesMut::new();
    settings.encode(&mut buf);
    write_frame(send, Frame::SETTINGS.0, &buf).await
}

// ── CONNECT handshake ──────────────────────────────────────

async fn read_connect_request(
    recv: &mut compio_quic::RecvStream,
) -> Result<ConnectRequest, ServerError> {
    let (typ, payload) = read_frame(recv).await
        .map_err(|e| ServerError::Read(e))?;
    if typ != Frame::HEADERS.0 {
        return Err(ServerError::Connect(web_transport_proto::ConnectError::UnexpectedFrame(Frame(typ))));
    }
    ConnectRequest::decode(&mut &payload[..]).map_err(ServerError::from)
}

async fn write_connect_response(
    send: &mut compio_quic::SendStream,
    response: &ConnectResponse,
) -> Result<(), ServerError> {
    let mut buf = BytesMut::new();
    response.encode(&mut buf).map_err(|e| ServerError::Connect(e))?;
    write_frame(send, Frame::HEADERS.0, &buf).await
        .map_err(|e| ServerError::Write(e))
}

async fn write_connect_request(
    send: &mut compio_quic::SendStream,
    request: &ConnectRequest,
) -> Result<(), String> {
    let mut buf = BytesMut::new();
    request.encode(&mut buf).map_err(|e| e.to_string())?;
    write_frame(send, Frame::HEADERS.0, &buf).await
}

async fn read_connect_response(
    recv: &mut compio_quic::RecvStream,
) -> Result<ConnectResponse, String> {
    let (typ, payload) = read_frame(recv).await?;
    if typ != Frame::HEADERS.0 {
        return Err(format!("expected HEADERS frame, got {typ:?}"));
    }
    ConnectResponse::decode(&mut &payload[..]).map_err(|e| e.to_string())
}

// ── Varint helpers ─────────────────────────────────────────

async fn read_varint(recv: &mut compio_quic::RecvStream) -> Result<VarInt, String> {
    let mut buf = [0u8; 8];
    recv.read_exact(&mut buf[..1]).await.map_err(|e| format!("read varint: {e}"))?;
    let tag = buf[0];
    let len: usize = match tag >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return Err("invalid varint tag".into()),
    };
    if len > 1 {
        recv.read_exact(&mut buf[1..len]).await.map_err(|e| format!("read varint: {e}"))?;
    }
    VarInt::decode(&mut &buf[..len]).map_err(|e| e.to_string())
}

fn encode_varint(v: VarInt) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    v.encode(&mut buf);
    buf
}
