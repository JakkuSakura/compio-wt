//! HTTP/3 SETTINGS exchange and WebTransport CONNECT handshake.

use bytes::BytesMut;
use web_transport_proto::{
    ConnectRequest, ConnectResponse, Frame, Settings, StreamUni, VarInt,
};

use crate::error::ServerError;

/// Perform the server-side HTTP/3 SETTINGS exchange and CONNECT handshake.
pub async fn server_accept(
    conn: &compio_quic::Connection,
    mut send: compio_quic::SendStream,
    mut recv: compio_quic::RecvStream,
) -> Result<(ConnectRequest, ConnectResponse), ServerError> {
    // 1. Accept peer's unidirectional control stream → read SETTINGS
    let mut control_recv = conn.accept_uni().await.map_err(ServerError::from)?;
    let settings = read_settings(&mut control_recv).await?;
    if settings.supports_webtransport() == 0 {
        return Err(ServerError::Settings("peer does not support WebTransport".into()));
    }

    // 2. Open our control stream → write SETTINGS with WebTransport enabled
    let mut control_send = conn.open_uni().map_err(|e| ServerError::Write(e.to_string()))?;
    let mut our_settings = Settings::default();
    our_settings.enable_webtransport(1);
    write_settings(&mut control_send, &our_settings).await?;

    // 3. Read CONNECT request from the bidirectional stream
    let request = read_connect_request(&mut recv).await?;

    // 4. Write 200 OK
    let response = ConnectResponse::OK;
    write_connect_response(&mut send, &response).await?;

    Ok((request, response))
}

// ── Frame I/O ──────────────────────────────────────────────

async fn read_frame(recv: &mut compio_quic::RecvStream) -> Result<(VarInt, Vec<u8>), ServerError> {
    let typ = read_varint(recv).await.map_err(ServerError::Read)?;
    let len = read_varint(recv).await.map_err(ServerError::Read)?;
    let mut payload = vec![0u8; len.into_inner() as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| ServerError::Read(format!("frame payload: {e}")))?;
    Ok((typ, payload))
}

async fn write_frame(
    send: &mut compio_quic::SendStream,
    typ: VarInt,
    payload: &[u8],
) -> Result<(), ServerError> {
    let typ_enc = encode_varint(typ);
    let len_enc = encode_varint(VarInt::from_u32(payload.len() as u32));
    send.write_all(&typ_enc).await.map_err(|e| ServerError::Write(format!("frame type: {e}")))?;
    send.write_all(&len_enc).await.map_err(|e| ServerError::Write(format!("frame len: {e}")))?;
    send.write_all(payload).await.map_err(|e| ServerError::Write(format!("frame payload: {e}")))?;
    Ok(())
}

// ── Settings ───────────────────────────────────────────────

async fn read_settings(recv: &mut compio_quic::RecvStream) -> Result<Settings, ServerError> {
    let st = read_varint(recv).await.map_err(ServerError::Read)?;
    if st != StreamUni::CONTROL.0 {
        return Err(ServerError::Settings("expected CONTROL stream".into()));
    }
    let (typ, payload) = read_frame(recv).await?;
    if typ != Frame::SETTINGS.0 {
        return Err(ServerError::Settings("expected SETTINGS frame".into()));
    }
    Settings::decode(&mut &payload[..]).map_err(|e| ServerError::Settings(e.to_string()))
}

async fn write_settings(
    send: &mut compio_quic::SendStream,
    settings: &Settings,
) -> Result<(), ServerError> {
    let st = encode_varint(StreamUni::CONTROL.0);
    send.write_all(&st).await.map_err(|e| ServerError::Write(e.to_string()))?;
    let mut buf = BytesMut::new();
    settings.encode(&mut buf);
    write_frame(send, Frame::SETTINGS.0, &buf).await
}

// ── CONNECT handshake ──────────────────────────────────────

async fn read_connect_request(
    recv: &mut compio_quic::RecvStream,
) -> Result<ConnectRequest, ServerError> {
    let (typ, payload) = read_frame(recv).await?;
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
