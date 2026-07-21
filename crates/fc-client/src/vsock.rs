//! Hybrid-vsock helpers.
//!
//! Firecracker's vsock device is *hybrid*: on the host it is a plain unix
//! domain socket, so no host vhost/vsock kernel support is needed.
//!
//! * **Host → guest** (this host connecting to a guest listener): connect to
//!   the device's `uds_path`, send `CONNECT <port>\n`, and expect `OK
//!   <host_port>\n`; thereafter the stream is a raw byte pipe to the guest.
//!   [`connect_to_guest`] performs that handshake.
//! * **Guest → host** (guest connecting out to a host listener): the host must
//!   already be listening on `"<uds_path>_<port>"`. [`host_listener`] binds
//!   that socket.
//!
//! M2 builds the length-prefixed RPC on top of the raw stream returned here.

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{Error, Result};

/// Upper bound on the handshake reply line length (guards against a peer that
/// never sends a newline).
const MAX_HANDSHAKE_LINE: usize = 128;

/// Connects to a guest vsock `port` through the host-side `uds_path` and
/// performs the `CONNECT`/`OK` handshake.
///
/// On success the returned [`UnixStream`] is a raw, bidirectional byte pipe to
/// the guest socket — the handshake bytes have been fully consumed and no guest
/// payload is buffered away (the reply is read one byte at a time up to the
/// terminating newline).
///
/// # Errors
/// * [`Error::VsockHandshake`] if the reply is not a well-formed `OK <port>`
///   line (wrong prefix, closed stream, or overlong).
/// * [`Error::Io`] if connecting or the socket read/write fails.
pub async fn connect_to_guest(uds_path: impl AsRef<Path>, port: u32) -> Result<UnixStream> {
    let uds_path = uds_path.as_ref();
    let mut stream = UnixStream::connect(uds_path)
        .await
        .map_err(|source| Error::Io {
            context: format!("connecting to vsock UDS {}", uds_path.display()),
            source,
        })?;

    let request = format!("CONNECT {port}\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|source| Error::Io {
            context: format!("sending vsock CONNECT to {}", uds_path.display()),
            source,
        })?;

    let line = read_line(&mut stream, uds_path, port).await?;
    // Firecracker replies "OK <assigned_host_port>\n" on success, or closes /
    // sends nothing on failure.
    match line.strip_prefix("OK ") {
        Some(rest) => {
            let host_port = rest.trim_end_matches(['\r', '\n']);
            if host_port.parse::<u32>().is_err() {
                return Err(Error::VsockHandshake {
                    path: uds_path.display().to_string(),
                    port,
                    reason: format!("malformed OK reply: {line:?}"),
                });
            }
            Ok(stream)
        }
        None => Err(Error::VsockHandshake {
            path: uds_path.display().to_string(),
            port,
            reason: format!("unexpected reply: {line:?}"),
        }),
    }
}

/// Reads a single `\n`-terminated line, one byte at a time, so no bytes past
/// the newline are consumed from the stream.
async fn read_line(stream: &mut UnixStream, uds_path: &Path, port: u32) -> Result<String> {
    let mut buf = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.map_err(|source| Error::Io {
            context: format!("reading vsock handshake reply from {}", uds_path.display()),
            source,
        })?;
        if n == 0 {
            return Err(Error::VsockHandshake {
                path: uds_path.display().to_string(),
                port,
                reason: "stream closed before handshake reply".to_string(),
            });
        }
        if byte[0] == b'\n' {
            buf.push(byte[0]);
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= MAX_HANDSHAKE_LINE {
            return Err(Error::VsockHandshake {
                path: uds_path.display().to_string(),
                port,
                reason: "handshake reply exceeded maximum line length".to_string(),
            });
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Binds a host listener for **guest-initiated** connections to `port`.
///
/// Firecracker expects the host to be listening on `"<uds_path>_<port>"`; this
/// removes any stale socket at that path and binds a fresh [`UnixListener`].
///
/// # Errors
/// [`Error::Io`] if the socket cannot be bound.
pub fn host_listener(uds_path: impl AsRef<Path>, port: u32) -> Result<UnixListener> {
    let path = format!("{}_{}", uds_path.as_ref().display(), port);
    // A stale socket file would make bind() fail with EADDRINUSE.
    let _ = std::fs::remove_file(&path);
    UnixListener::bind(&path).map_err(|source| Error::Io {
        context: format!("binding host vsock listener at {path}"),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawns a mock unix listener that speaks the Firecracker host-side vsock
    /// handshake, then drives [`connect_to_guest`] against it.
    #[tokio::test]
    async fn connect_handshake_ok() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            // Read the "CONNECT 52\n" request.
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            loop {
                let n = conn.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                req.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            assert_eq!(req, b"CONNECT 52\n");
            conn.write_all(b"OK 1024\n").await.unwrap();
            // Echo one payload byte to prove the stream is usable afterwards.
            let mut payload = [0u8; 1];
            conn.read_exact(&mut payload).await.unwrap();
            conn.write_all(&payload).await.unwrap();
        });

        let mut stream = connect_to_guest(&sock, 52).await.expect("handshake ok");
        // The stream is a raw pipe now: round-trip a byte.
        stream.write_all(b"Z").await.unwrap();
        let mut echoed = [0u8; 1];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"Z");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_handshake_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 1];
            while let Ok(n) = conn.read(&mut b).await {
                if n == 0 || b[0] == b'\n' {
                    break;
                }
            }
            // Firecracker signals a refused connection by closing the socket.
            drop(conn);
        });

        let err = connect_to_guest(&sock, 52).await.expect_err("should fail");
        assert!(matches!(err, Error::VsockHandshake { port: 52, .. }));
    }

    #[tokio::test]
    async fn host_listener_binds_port_suffixed_path() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock.sock");
        let listener = host_listener(&base, 52).expect("bind");
        let expected = format!("{}_{}", base.display(), 52);
        assert!(std::path::Path::new(&expected).exists());
        // Re-binding the same port must succeed (stale socket is cleared).
        drop(listener);
        let _again = host_listener(&base, 52).expect("rebind after stale");
    }
}
