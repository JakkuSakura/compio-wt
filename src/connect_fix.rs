// IoBuf API helpers for compio-quic 0.8+

use compio::buf::bytes::Bytes;

async fn read_exact(recv: &mut compio_quic::RecvStream, buf: &mut [u8]) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = buf.len() - filled;
        let mut chunk = Bytes::from(vec![0u8; remaining.min(65536)]);
        match recv.read_chunks(&mut [chunk]).await.map_err(|e| format!("read: {e:?}"))? {
            Some(_) => {
                let n = chunk.len().min(remaining);
                buf[filled..filled + n].copy_from_slice(&chunk[..n]);
                filled += n;
            }
            None => return Err("stream ended early".into()),
        }
    }
    Ok(())
}
