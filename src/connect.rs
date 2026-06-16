//! HTTP/3 SETTINGS exchange and WebTransport CONNECT handshake.

use bytes::BytesMut;
use web_transport_proto::{
    ConnectRequest, ConnectResponse, Frame, Settings, StreamUni, VarInt,
};

use compio::buf::bytes::Bytes;
use crate::error::{ClientError, ServerError};

pub async fn server_accept(
    _conn: &compio_quic::Connection,
    mut send: compio_quic::SendStream,
    mut recv: compio_quic::RecvStream,
) -> Result<(ConnectRequest, ConnectResponse), ServerError> {
    let settings = read_settings(&mut recv).await?;
    write_settings(&mut send, &settings).await.map_err(|e| ServerError::Write(e))?;
    let request = read_connect_request(&mut recv).await?;
    let response = ConnectResponse::default();
    write_connect_response(&mut send, &response).await?;
    Ok((request, response))
}

pub async fn client_connect(
    _conn: &compio_quic::Connection,
    mut send: compio_quic::SendStream,
    mut recv: compio_quic::RecvStream,
    request: &ConnectRequest,
) -> Result<ConnectResponse, ClientError> {
    write_settings(&mut send, &Settings::default()).await.map_err(|e| ClientError::Write(e))?;
    read_settings(&mut recv).await?;
    write_connect_request(&mut send, request).await.map_err(|e| ClientError::Write(e))?;
    let response = read_connect_response(&mut recv).await.map_err(|e| ClientError::Read(e))?;
    Ok(response)
}

async fn read_settings(recv: &mut compio_quic::RecvStream) -> Result<Settings, ServerError> {
    let stream_typ = read_varint(recv).await.map_err(|e| ServerError::Read(e))?;
    if stream_typ != StreamUni::CONTROL.0 {
        return Err(ServerError::Connect(
            web_transport_proto::ConnectError::UnexpectedFrame(Frame(stream_typ)),
        ));
    }
    let (typ, payload) = read_frame(recv).await.map_err(|e| ServerError::Read(e))?;
    if typ != Frame::SETTINGS.0 {
        return Err(ServerError::Connect(
            web_transport_proto::ConnectError::UnexpectedFrame(Frame(typ)),
        ));
    }
    Settings::decode(&mut &payload[..]).map_err(|_| ServerError::Settings("settings decode error".into()))
}

async fn read_frame(recv: &mut compio_quic::RecvStream) -> Result<(VarInt, Vec<u8>), String> {
    let typ = read_varint(recv).await?;
    let len = read_varint(recv).await?;
    let payload = read_exact_vec(recv, len.into_inner() as usize).await?;
    Ok((typ, payload))
}

async fn write_frame(
    send: &mut compio_quic::SendStream,
    typ: VarInt,
    payload: &[u8],
) -> Result<(), String> {
    let typ_enc = encode_varint(typ);
    let len_enc = encode_varint(VarInt::from_u32(payload.len() as u32));
    send.write_all_chunks(&mut [Bytes::copy_from_slice(&typ_enc)])
        .await.map_err(|e| format!("frame type: {e}"))?;
    send.write_all_chunks(&mut [Bytes::copy_from_slice(&len_enc)])
        .await.map_err(|e| format!("frame len: {e}"))?;
    send.write_all_chunks(&mut [Bytes::copy_from_slice(payload)])
        .await.map_err(|e| format!("frame payload: {e}"))?;
    Ok(())
}

async fn write_settings(
    send: &mut compio_quic::SendStream,
    settings: &Settings,
) -> Result<(), String> {
    let st = encode_varint(StreamUni::CONTROL.0);
    send.write_all_chunks(&mut [Bytes::copy_from_slice(&st)])
        .await.map_err(|e| e.to_string())?;
    let mut buf = BytesMut::new();
    settings.encode(&mut buf);
    write_frame(send, Frame::SETTINGS.0, &buf).await
}

async fn read_connect_request(
    recv: &mut compio_quic::RecvStream,
) -> Result<ConnectRequest, ServerError> {
    let (typ, payload) = read_frame(recv).await.map_err(|e| ServerError::Read(e))?;
    if typ != Frame::HEADERS.0 {
        return Err(ServerError::Connect(
            web_transport_proto::ConnectError::UnexpectedFrame(Frame(typ)),
        ));
    }
    ConnectRequest::decode(&mut &payload[..]).map_err(ServerError::from)
}

async fn write_connect_response(
    send: &mut compio_quic::SendStream,
    response: &ConnectResponse,
) -> Result<(), ServerError> {
    let mut buf = BytesMut::new();
    response.encode(&mut buf).map_err(ServerError::Connect)?;
    write_frame(send, Frame::HEADERS.0, &buf).await.map_err(|e| ServerError::Write(e))
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
        return Err(format!("unexpected frame: {typ:?}"));
    }
    ConnectResponse::decode(&mut &payload[..]).map_err(|e| e.to_string())
}

async fn read_varint(recv: &mut compio_quic::RecvStream) -> Result<VarInt, String> {
    let mut buf = [0u8; 8];
    read_exact_slice(recv, &mut buf[..1]).await?;
    let tag = buf[0];
    let len: usize = match tag >> 6 { 0 => 1, 1 => 2, 2 => 4, 3 => 8, _ => return Err("invalid varint tag".into()) };
    if len > 1 { read_exact_slice(recv, &mut buf[1..len]).await?; }
    VarInt::decode(&mut &buf[..len]).map_err(|e| e.to_string())
}

fn encode_varint(v: VarInt) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8);
    v.encode(&mut buf);
    buf.to_vec()
}

async fn read_exact_slice(recv: &mut compio_quic::RecvStream, buf: &mut [u8]) -> Result<(), String> {
    let len = buf.len();
    let mut filled = 0;
    while filled < len {
        let remaining = len - filled;
        let mut bufs = vec![Bytes::from(vec![0u8; remaining.min(65536)])];
        match recv.read_chunks(&mut bufs).await.map_err(|e| format!("read: {e:?}"))? {
            Some(_) => {
                let n = bufs[0].len().min(remaining);
                buf[filled..filled + n].copy_from_slice(&bufs[0][..n]);
                filled += n;
            }
            None => return Err("stream ended early".into()),
        }
    }
    Ok(())
}

async fn read_exact_vec(recv: &mut compio_quic::RecvStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    read_exact_slice(recv, &mut buf).await?;
    Ok(buf)
}
