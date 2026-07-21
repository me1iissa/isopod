//! Length-prefixed JSON framing (sync for the guest, async behind the `tokio`
//! feature for the host).

use crate::MAX_FRAME_LEN;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};

/// Framing/codec failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O failure.
    #[error("frame io: {0}")]
    Io(#[from] std::io::Error),
    /// Peer announced a frame larger than [`MAX_FRAME_LEN`].
    #[error("frame length {0} exceeds cap {MAX_FRAME_LEN}")]
    TooLarge(u32),
    /// Payload was not valid JSON for the expected type.
    #[error("frame decode: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Write one message as a `u32`-LE-length-prefixed JSON frame.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(msg)?;
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON frame. Returns `Ok(None)` on clean EOF at a
/// frame boundary (peer closed the connection).
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, FrameError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(Some(serde_json::from_slice(&payload)?))
}

/// Async framing helpers (host side).
#[cfg(feature = "tokio")]
pub mod aio {
    use super::FrameError;
    use crate::MAX_FRAME_LEN;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// Async twin of [`super::write_frame`].
    pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
    where
        W: AsyncWrite + Unpin,
        T: Serialize,
    {
        let payload = serde_json::to_vec(msg)?;
        let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge(len));
        }
        w.write_all(&len.to_le_bytes()).await?;
        w.write_all(&payload).await?;
        w.flush().await?;
        Ok(())
    }

    /// Async twin of [`super::read_frame`].
    pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, FrameError>
    where
        R: AsyncRead + Unpin,
        T: DeserializeOwned,
    {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge(len));
        }
        let mut payload = vec![0u8; len as usize];
        r.read_exact(&mut payload).await?;
        Ok(Some(serde_json::from_slice(&payload)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Request, RequestOp};
    use std::io::Cursor;

    /// Reader that yields one byte per read call — exercises short reads.
    struct OneByte<R>(R);
    impl<R: Read> Read for OneByte<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    #[test]
    fn round_trip() {
        let msg = Request {
            id: 1,
            op: RequestOp::Ping,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        let got: Request = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn round_trip_survives_short_reads() {
        let msg = Request {
            id: 2,
            op: RequestOp::Halt { sync: true },
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        write_frame(
            &mut buf,
            &Request {
                id: 3,
                op: RequestOp::Ping,
            },
        )
        .unwrap();
        let mut r = OneByte(Cursor::new(&buf));
        let a: Request = read_frame(&mut r).unwrap().unwrap();
        let b: Request = read_frame(&mut r).unwrap().unwrap();
        assert_eq!(a.id, 2);
        assert_eq!(b.id, 3);
        assert!(read_frame::<_, Request>(&mut r).unwrap().is_none());
    }

    #[test]
    fn clean_eof_is_none_and_oversize_rejected() {
        let empty: Option<Request> = read_frame(&mut Cursor::new(&[])).unwrap();
        assert!(empty.is_none());

        let mut evil = Vec::new();
        evil.extend_from_slice(&(crate::MAX_FRAME_LEN + 1).to_le_bytes());
        match read_frame::<_, Request>(&mut Cursor::new(&evil)) {
            Err(FrameError::TooLarge(_)) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }
}
