//! Live integration test for the M3 stage overlay root.
//!
//! Boots the real `base.sqfs` (read-only squashfs, `/dev/vda`) with the guest
//! agent as PID 1 and drives the full commit→fork→whiteout stage chain through
//! four boots, proving the overlay assembly, `pivot_root`, and whiteout
//! semantics end-to-end:
//!
//! * **(a)** boots to a working vsock (`Ping` → `Pong`);
//! * **(b)** `touch /marker` lands in the *scratch* image's overlay upperdir
//!   (verified from the host with `debugfs` after halt) and `/proc/mounts` shows
//!   the overlay mounted on `/`;
//! * **(c)** a second boot with the previous scratch attached as a **layer** sees
//!   `/marker`, and `rm /marker` writes a whiteout char-device into the new
//!   scratch upper (verified with `debugfs`);
//! * **(d)** a third boot stacking **both** previous images as layers finds
//!   `/marker` gone (the newer layer's whiteout wins).
//!
//! Ignored by default. Requires `/dev/kvm`, the vendored Firecracker binary, the
//! CI kernel, and a `base-sqfs` image. Build and run:
//!
//! ```text
//! cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent
//! cargo run -p isopod-cli -- image build-rootfs --flavor base-sqfs
//!
//! ISOPOD_FC_BIN=~/.isopod/bin/firecracker \
//! ISOPOD_FC_KERNEL=~/.isopod/images/vmlinux-6.18.36 \
//! ISOPOD_BASE_SQFS=~/.isopod/images/base.sqfs \
//!   cargo test -p isopod-guest-agent --test live_overlay -- --ignored --nocapture
//! ```
//!
//! Set `ISOPOD_AGENT_SERIAL=1` to see the guest serial console inline. Scratch
//! drives are created with the same `isopod_core::image::make_scratch_ext4` the
//! host track uses. Every Firecracker process is torn down via `FcProcess`'s
//! `Drop` guard, so a panic mid-test leaves no leaked VMM.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use isopod_core::image::make_scratch_ext4;
use isopod_fc::models::{BootSource, Drive, MachineConfig, Vsock};
use isopod_fc::vsock::connect_to_guest;
use isopod_fc::{FcClient, FcProcess, FcProcessConfig, StdioMode, VmId};
use isopod_proto::frame::aio::{read_frame, write_frame};
use isopod_proto::{
    b64_decode, ExecRequest, ExecStreamKind, Request, RequestOp, Response, ResponseBody,
    PROTO_VERSION, VSOCK_PORT,
};
use tokio::net::UnixStream;

/// The optimized boot args shared with the other live tests; the overlay boot
/// appends ` isopod.layers=<N>`.
const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init quiet \
     i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1";

/// Guest context id for the vsock device.
const GUEST_CID: u32 = 3;

/// Apparent size of each scratch drive (sparse on disk).
const SCRATCH_MIB: u64 = 64;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

/// The captured result of one in-guest command.
#[derive(Debug)]
struct CmdOut {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

async fn connect(uds: &Path) -> std::io::Result<UnixStream> {
    connect_to_guest(uds, VSOCK_PORT)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
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

/// Send one request and read exactly one response frame.
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

/// Run one `/bin/sh -c <script>` and collect its full stdout/stderr + exit code.
async fn run_script(uds: &Path, id: u64, script: &str) -> CmdOut {
    let mut s = connect(uds).await.expect("vsock connect");
    write_frame(
        &mut s,
        &Request {
            id,
            op: RequestOp::Exec(ExecRequest {
                argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
                env: vec![],
                cwd: None,
                timeout_ms: Some(10_000),
                stdin_b64: None,
            }),
        },
    )
    .await
    .expect("write exec");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    while let Some(resp) = read_frame::<_, Response>(&mut s).await.expect("read frame") {
        match resp.body {
            ResponseBody::ExecStream { stream, data_b64 } => {
                let bytes = b64_decode(&data_b64).expect("valid base64");
                match stream {
                    ExecStreamKind::Stdout => stdout.extend_from_slice(&bytes),
                    ExecStreamKind::Stderr => stderr.extend_from_slice(&bytes),
                }
            }
            ResponseBody::ExecDone { exit_code: ec, .. } => {
                exit_code = ec;
                break;
            }
            ResponseBody::Error { message } => {
                stderr.extend_from_slice(message.as_bytes());
                break;
            }
            other => panic!("unexpected exec frame: {other:?}"),
        }
    }
    CmdOut {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code,
    }
}

/// Boot `base` (ro root) + `layers` (ro) + `scratch` (rw) with
/// `isopod.layers=<layers.len()>`, wait for the agent, run each script in order,
/// then halt and wait for Firecracker to exit. Returns the `Pong` body and the
/// per-script outputs.
#[allow(clippy::too_many_arguments)]
async fn boot_overlay_run_halt(
    fc_bin: &Path,
    kernel: &Path,
    base: &Path,
    layers: &[PathBuf],
    scratch: &Path,
    work: &Path,
    id: &str,
    scripts: &[&str],
) -> (ResponseBody, Vec<CmdOut>) {
    let api_sock = work.join(format!("{id}-api.sock"));
    let vsock_uds = work.join(format!("{id}-vsock.sock"));

    let stdio = if std::env::var_os("ISOPOD_AGENT_SERIAL").is_some() {
        StdioMode::Inherit
    } else {
        StdioMode::Null
    };

    let mut proc = FcProcess::spawn(
        FcProcessConfig::new(fc_bin, &api_sock)
            .id(VmId::new(id).expect("valid id"))
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
    let cmdline = format!("{BOOT_ARGS} isopod.layers={}", layers.len());
    client
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), &cmdline))
        .await
        .expect("boot-source");

    // PUT order == guest device order: base (vda, root, ro), each layer
    // (vdb.. ro, bottom-to-top), then the writable scratch last (rw).
    client
        .put_drive(&Drive::virtio("rootfs", base.to_string_lossy(), true, true))
        .await
        .expect("drive base");
    for (i, layer) in layers.iter().enumerate() {
        let drive_id = format!("layer{}", i + 1);
        client
            .put_drive(&Drive::virtio(
                &drive_id,
                layer.to_string_lossy(),
                false,
                true,
            ))
            .await
            .expect("drive layer");
    }
    client
        .put_drive(&Drive::virtio(
            "scratch",
            scratch.to_string_lossy(),
            false,
            false,
        ))
        .await
        .expect("drive scratch");

    client
        .put_vsock(&Vsock::new(GUEST_CID, vsock_uds.to_string_lossy()))
        .await
        .expect("vsock");
    client.instance_start().await.expect("InstanceStart");
    assert!(
        wait_running(&client, Duration::from_secs(10)).await,
        "{id}: guest never reached Running"
    );

    let pong = wait_for_agent(&vsock_uds, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| panic!("{id}: agent never answered Ping"));

    let mut outs = Vec::new();
    for (n, script) in scripts.iter().enumerate() {
        let out = run_script(&vsock_uds, 100 + n as u64, script).await;
        eprintln!(
            "[{id}] $ {script}\n    exit={:?} stdout={:?} stderr={:?}",
            out.exit_code, out.stdout, out.stderr
        );
        outs.push(out);
    }

    let ack = rpc_single(&vsock_uds, 9, RequestOp::Halt { sync: true }).await;
    assert!(
        matches!(ack.body, ResponseBody::Ok),
        "{id}: Halt should ack Ok, got {:?}",
        ack.body
    );

    // Firecracker should exit shortly after the guest powers off; force if not.
    let exited = {
        let deadline = Instant::now() + Duration::from_secs(5);
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
    if !exited {
        let _ = proc.shutdown(Duration::from_secs(2)).await;
    }
    assert!(exited, "{id}: Firecracker did not exit after Halt");

    (pong.body, outs)
}

/// Run a one-shot `debugfs -R "<cmd>" <img>` and return its stdout (debugfs
/// prints its version banner to stderr, which is echoed for context).
fn debugfs(img: &Path, cmd: &str) -> String {
    let out = Command::new("debugfs")
        .arg("-R")
        .arg(cmd)
        .arg(img)
        .output()
        .expect("spawn debugfs (is e2fsprogs installed?)");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!(
        "debugfs -R '{cmd}' {}\n{stdout}--- (debugfs stderr) {}",
        img.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    stdout
}

#[tokio::test]
#[ignore = "requires ISOPOD_FC_BIN/KERNEL, ISOPOD_BASE_SQFS, and /dev/kvm"]
async fn live_overlay_stage_chain() {
    let (Some(fc_bin), Some(kernel), Some(base)) = (
        env_path("ISOPOD_FC_BIN"),
        env_path("ISOPOD_FC_KERNEL"),
        env_path("ISOPOD_BASE_SQFS"),
    ) else {
        eprintln!("SKIP: set ISOPOD_FC_BIN, ISOPOD_FC_KERNEL, ISOPOD_BASE_SQFS to run this test");
        return;
    };
    for (label, p) in [
        ("FC_BIN", &fc_bin),
        ("KERNEL", &kernel),
        ("BASE_SQFS", &base),
    ] {
        assert!(p.exists(), "{label} does not exist: {}", p.display());
    }

    let work = tempfile::tempdir().expect("tempdir");
    let scratch_a = work.path().join("scratch-a.ext4");
    let scratch_b = work.path().join("scratch-b.ext4");
    let scratch_c = work.path().join("scratch-c.ext4");
    for s in [&scratch_a, &scratch_b, &scratch_c] {
        make_scratch_ext4(s, SCRATCH_MIB).expect("make scratch");
    }

    // ---- Boot 1: layers=0, fresh scratch_a. (a) ping, (b) touch /marker -------
    let (pong, outs) = boot_overlay_run_halt(
        &fc_bin,
        &kernel,
        &base,
        &[],
        &scratch_a,
        work.path(),
        "iso-ovl-1",
        &["touch /marker && cat /proc/mounts"],
    )
    .await;
    // (a)
    let ResponseBody::Pong {
        proto_version,
        uptime_s,
        ..
    } = &pong
    else {
        panic!("expected Pong, got {pong:?}");
    };
    assert_eq!(*proto_version, PROTO_VERSION, "proto version");
    assert!(
        *uptime_s > 0.0 && *uptime_s < 120.0,
        "fresh-boot uptime {uptime_s}"
    );
    // (b) overlay is the root filesystem.
    assert_eq!(outs[0].exit_code, Some(0), "touch+mounts exit 0");
    assert!(
        outs[0].stdout.contains("overlay / overlay"),
        "overlay must be mounted on / — /proc/mounts was:\n{}",
        outs[0].stdout
    );
    // (b) the marker landed in scratch_a's overlay upperdir.
    let ls_a = debugfs(&scratch_a, "ls -l /upper");
    assert!(
        ls_a.contains("marker"),
        "scratch_a /upper should contain the marker file; debugfs said:\n{ls_a}"
    );

    // ---- Boot 2: layers=1 (scratch_a as layer), fresh scratch_b. (c) ----------
    let (_pong, outs) = boot_overlay_run_halt(
        &fc_bin,
        &kernel,
        &base,
        std::slice::from_ref(&scratch_a),
        &scratch_b,
        work.path(),
        "iso-ovl-2",
        &[
            "ls -l /marker",
            "rm /marker",
            "[ -e /marker ] && echo STILL-PRESENT || echo GONE-THIS-BOOT",
        ],
    )
    .await;
    // The layer's file is visible.
    assert_eq!(outs[0].exit_code, Some(0), "ls /marker sees the layer file");
    assert!(
        outs[0].stdout.contains("marker"),
        "ls output: {:?}",
        outs[0]
    );
    // rm succeeds, and within this boot the whiteout already hides it.
    assert_eq!(outs[1].exit_code, Some(0), "rm /marker succeeds");
    assert!(
        outs[2].stdout.contains("GONE-THIS-BOOT"),
        "marker should be hidden after rm: {:?}",
        outs[2]
    );
    // (c) the deletion is recorded as a whiteout char-device in scratch_b's upper.
    let ls_b = debugfs(&scratch_b, "ls -l /upper");
    assert!(
        ls_b.contains("marker"),
        "scratch_b /upper should contain the whiteout entry; debugfs said:\n{ls_b}"
    );
    let stat_b = debugfs(&scratch_b, "stat /upper/marker");
    assert!(
        stat_b.contains("character special")
            || stat_b.contains("Device major/minor number: 00, 00")
            || stat_b.to_lowercase().contains("char"),
        "scratch_b /upper/marker should be a whiteout char-device; debugfs stat said:\n{stat_b}"
    );

    // ---- Boot 3: layers=2 (scratch_a bottom, scratch_b top), fresh scratch_c --
    let (_pong, outs) = boot_overlay_run_halt(
        &fc_bin,
        &kernel,
        &base,
        &[scratch_a.clone(), scratch_b.clone()],
        &scratch_c,
        work.path(),
        "iso-ovl-3",
        &["[ -e /marker ] && echo PRESENT || echo GONE"],
    )
    .await;
    // (d) the newer layer's whiteout wins: the marker is gone.
    assert!(
        outs[0].stdout.contains("GONE"),
        "with both layers stacked the whiteout must win: {:?}",
        outs[0]
    );
    assert!(
        !outs[0].stdout.contains("PRESENT"),
        "marker unexpectedly visible: {:?}",
        outs[0]
    );
}
