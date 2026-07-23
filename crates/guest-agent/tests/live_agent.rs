//! Live integration test: boot a real Firecracker microVM whose PID 1 is the
//! `isopod-guest-agent`, then drive its vsock RPC end-to-end.
//!
//! Ignored by default. It needs `/dev/kvm`, the vendored Firecracker binary, the
//! CI kernel, and a **`dev-agent`** rootfs (the busybox base with the agent as
//! `/sbin/init`). Build the rootfs first, then run:
//!
//! ```text
//! cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent
//! cargo run -p isopod-cli -- image build-rootfs --flavor dev-agent
//!
//! ISOPOD_FC_BIN=~/.isopod/bin/firecracker \
//! ISOPOD_FC_KERNEL=~/.isopod/images/vmlinux-6.18.36 \
//! ISOPOD_AGENT_ROOTFS=~/.isopod/images/rootfs-dev-agent.ext4 \
//!   cargo test -p isopod-guest-agent --test live_agent -- --ignored --nocapture
//! ```
//!
//! Set `ISOPOD_AGENT_SERIAL=1` to see the guest serial console (the agent's
//! `ISOPOD-*` markers and `[isopod-agent]` logs) inline.
//!
//! The rootfs is copied to a scratch file before booting — the original is never
//! attached. Every Firecracker process is torn down via `FcProcess`'s `Drop`
//! guard, so a panic mid-test still leaves no leaked VMM.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use isopod_fc::models::{BootSource, Drive, MachineConfig, Vsock};
use isopod_fc::vsock::connect_to_guest;
use isopod_fc::{FcClient, FcProcess, FcProcessConfig, StdioMode, VmId};
use isopod_proto::frame::aio::{read_frame, write_frame};
use isopod_proto::{
    b64_decode, ExecRequest, ExecStreamKind, Request, RequestOp, Response, ResponseBody,
    PROTO_VERSION, VSOCK_PORT,
};
use tokio::net::UnixStream;

/// Same optimized boot args the M1 live test uses.
const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init quiet \
     i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1";

/// Guest context id for the vsock device.
const GUEST_CID: u32 = 3;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

async fn wait_running(client: &FcClient, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(info) = client.get_instance_info().await {
            if info.state.is_running() {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Open a fresh vsock connection to the agent (one connection per operation).
async fn connect(uds: &Path) -> std::io::Result<UnixStream> {
    connect_to_guest(uds, VSOCK_PORT)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Send one request and read exactly one response frame (Ping / SyncClock /
/// PutFile / GetFile / Halt).
async fn rpc_single(uds: &Path, id: u64, op: RequestOp) -> Response {
    let mut s = connect(uds).await.expect("vsock connect");
    write_frame(&mut s, &Request { id, op })
        .await
        .expect("write request");
    read_frame::<_, Response>(&mut s)
        .await
        .expect("read response")
        .expect("one response frame")
}

/// Run an exec and collect every response frame up to and including `ExecDone`
/// (or a terminal `Error`).
async fn exec_collect(uds: &Path, id: u64, req: ExecRequest) -> Vec<Response> {
    let mut s = connect(uds).await.expect("vsock connect");
    write_frame(
        &mut s,
        &Request {
            id,
            op: RequestOp::Exec(req),
        },
    )
    .await
    .expect("write exec");
    let mut frames = Vec::new();
    while let Some(resp) = read_frame::<_, Response>(&mut s).await.expect("read frame") {
        let terminal = matches!(
            resp.body,
            ResponseBody::ExecDone { .. } | ResponseBody::Error { .. }
        );
        frames.push(resp);
        if terminal {
            break;
        }
    }
    frames
}

/// Poll `Ping` until the agent's vsock server answers, or the deadline passes.
async fn wait_for_agent(uds: &Path, timeout: Duration) -> Option<Response> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(mut s) = connect(uds).await {
            if write_frame(
                &mut s,
                &Request {
                    id: 0,
                    op: RequestOp::Ping,
                },
            )
            .await
            .is_ok()
            {
                if let Ok(Some(resp)) = read_frame::<_, Response>(&mut s).await {
                    return Some(resp);
                }
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Concatenate the base64-decoded chunks of one stream from a set of exec frames.
fn collect_stream(frames: &[Response], want: ExecStreamKind) -> String {
    let mut out = Vec::new();
    for f in frames {
        if let ResponseBody::ExecStream { stream, data_b64 } = &f.body {
            if *stream == want {
                out.extend_from_slice(&b64_decode(data_b64).expect("valid base64"));
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
#[ignore = "requires ISOPOD_FC_BIN/KERNEL, a dev-agent ISOPOD_AGENT_ROOTFS, and /dev/kvm"]
async fn live_agent_exec_rpc() {
    let (Some(fc_bin), Some(kernel), Some(rootfs_src)) = (
        env_path("ISOPOD_FC_BIN"),
        env_path("ISOPOD_FC_KERNEL"),
        env_path("ISOPOD_AGENT_ROOTFS"),
    ) else {
        eprintln!(
            "SKIP: set ISOPOD_FC_BIN, ISOPOD_FC_KERNEL, ISOPOD_AGENT_ROOTFS to run this test"
        );
        return;
    };
    for (label, p) in [
        ("FC_BIN", &fc_bin),
        ("KERNEL", &kernel),
        ("ROOTFS", &rootfs_src),
    ] {
        assert!(p.exists(), "{label} does not exist: {}", p.display());
    }

    let work = tempfile::tempdir().expect("tempdir");
    let base = work.path();
    let rootfs = base.join("rootfs.ext4");
    std::fs::copy(&rootfs_src, &rootfs).expect("copy rootfs");
    let api_sock = base.join("api.sock");
    let vsock_uds = base.join("vsock.sock");

    let stdio = if std::env::var_os("ISOPOD_AGENT_SERIAL").is_some() {
        StdioMode::Inherit
    } else {
        StdioMode::Null
    };

    let mut proc = FcProcess::spawn(
        FcProcessConfig::new(&fc_bin, &api_sock)
            .id(VmId::new("isopod-agent-live").expect("valid id"))
            .stdio(stdio)
            .socket_timeout(Duration::from_secs(10)),
    )
    .await
    .expect("spawn firecracker");

    let client = proc.client().expect("client");
    client
        .put_machine_config(&MachineConfig::new(1, 256))
        .await
        .expect("machine-config");
    client
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), BOOT_ARGS))
        .await
        .expect("boot-source");
    client
        .put_drive(&Drive::virtio(
            "rootfs",
            rootfs.to_string_lossy(),
            true,
            false,
        ))
        .await
        .expect("drive");
    // Configure the hybrid vsock device before boot.
    client
        .put_vsock(&Vsock::new(GUEST_CID, vsock_uds.to_string_lossy()))
        .await
        .expect("vsock");

    client.instance_start().await.expect("InstanceStart");
    assert!(
        wait_running(&client, Duration::from_secs(10)).await,
        "guest never reached Running"
    );

    // ---- (a) Ping -> Pong -------------------------------------------------
    let pong = wait_for_agent(&vsock_uds, Duration::from_secs(15))
        .await
        .expect("agent answered Ping");
    eprintln!("PING -> {pong:?}");
    let ResponseBody::Pong {
        proto_version,
        uptime_s,
        agent_version,
        overlay_error,
    } = &pong.body
    else {
        panic!("expected Pong, got {:?}", pong.body);
    };
    assert_eq!(*proto_version, PROTO_VERSION, "proto_version must be 1");
    assert!(!agent_version.is_empty(), "agent_version present");
    assert_eq!(
        *overlay_error, None,
        "a healthy boot must report no overlay-assembly error"
    );
    assert!(
        *uptime_s > 0.0 && *uptime_s < 120.0,
        "uptime {uptime_s} should be a plausible fresh-boot value"
    );

    // ---- (b) Exec streams stdout + stderr, exit code 3 --------------------
    let frames = exec_collect(
        &vsock_uds,
        1,
        ExecRequest {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo hello-from-guest; echo err >&2; exit 3".into(),
            ],
            env: vec![],
            cwd: None,
            timeout_ms: None,
            stdin_b64: None,
        },
    )
    .await;
    eprintln!("EXEC(echo) frames:");
    for f in &frames {
        eprintln!("  {f:?}");
    }
    let stdout = collect_stream(&frames, ExecStreamKind::Stdout);
    let stderr = collect_stream(&frames, ExecStreamKind::Stderr);
    assert!(stdout.contains("hello-from-guest"), "stdout was {stdout:?}");
    assert!(stderr.contains("err"), "stderr was {stderr:?}");
    let done = frames.last().expect("at least one frame");
    let ResponseBody::ExecDone {
        exit_code,
        timed_out,
        ..
    } = &done.body
    else {
        panic!("expected ExecDone last, got {:?}", done.body);
    };
    assert_eq!(*exit_code, Some(3), "exit code must be 3");
    assert!(!*timed_out, "should not have timed out");

    // ---- (c) Exec timeout: sleep 10 with a 500 ms budget ------------------
    let t = Instant::now();
    let frames = exec_collect(
        &vsock_uds,
        2,
        ExecRequest {
            argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
            env: vec![],
            cwd: None,
            timeout_ms: Some(500),
            stdin_b64: None,
        },
    )
    .await;
    let elapsed = t.elapsed();
    let done = frames.last().expect("exec done");
    eprintln!("EXEC(sleep,timeout) -> {:?} in {:?}", done.body, elapsed);
    let ResponseBody::ExecDone {
        timed_out, signal, ..
    } = &done.body
    else {
        panic!("expected ExecDone, got {:?}", done.body);
    };
    assert!(*timed_out, "sleep 10 with a 500ms budget must time out");
    assert_eq!(*signal, Some(9), "timed-out child is SIGKILLed");
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout should fire fast, took {elapsed:?}"
    );

    // ---- SyncClock + PutFile/GetFile round-trip ---------------------------
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch");
    let clock = rpc_single(
        &vsock_uds,
        10,
        RequestOp::SyncClock {
            unix_secs: now.as_secs(),
            nanos: now.subsec_nanos(),
        },
    )
    .await;
    eprintln!("SYNC_CLOCK -> {:?}", clock.body);
    assert!(matches!(clock.body, ResponseBody::Ok), "SyncClock -> Ok");

    let payload = b"written-by-host\n";
    let put = rpc_single(
        &vsock_uds,
        11,
        RequestOp::PutFile {
            path: "/root/hello.txt".into(),
            mode: 0o644,
            data_b64: isopod_proto::b64_encode(payload),
        },
    )
    .await;
    eprintln!("PUT_FILE -> {:?}", put.body);
    assert!(matches!(put.body, ResponseBody::Ok), "PutFile -> Ok");

    let got = rpc_single(
        &vsock_uds,
        12,
        RequestOp::GetFile {
            path: "/root/hello.txt".into(),
            max_bytes: 4096,
        },
    )
    .await;
    let ResponseBody::File { data_b64, mode } = &got.body else {
        panic!("expected File, got {:?}", got.body);
    };
    let round = b64_decode(data_b64).expect("valid base64");
    eprintln!("GET_FILE -> {} bytes, mode {:o}", round.len(), mode & 0o777);
    assert_eq!(round, payload, "GetFile round-trips the written bytes");
    assert_eq!(mode & 0o777, 0o644, "GetFile reports the chmod'd mode");

    // ---- (d) Halt powers the VM off ---------------------------------------
    let ack = rpc_single(&vsock_uds, 3, RequestOp::Halt { sync: true }).await;
    eprintln!("HALT -> {:?}", ack.body);
    assert!(
        matches!(ack.body, ResponseBody::Ok),
        "Halt should ack Ok, got {:?}",
        ack.body
    );

    // Firecracker should exit within ~2s of the guest powering off.
    let exited = {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if matches!(proc.try_wait(), Ok(Some(_))) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    assert!(exited, "Firecracker did not exit after Halt");
    eprintln!("HALT: firecracker exited cleanly");

    // Belt-and-braces: ensure no VMM is left behind even if the poweroff raced
    // (a no-op if it already exited above).
    let _ = proc.shutdown(Duration::from_secs(2)).await;
}
