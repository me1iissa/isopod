//! Live integration test for the guest network-config path with **no NIC
//! attached**.
//!
//! It boots a real `dev-agent` microVM whose kernel command line carries
//! `isopod.net=…`/`isopod.gw=…`/`isopod.dns=…` but attaches **no**
//! `network-interfaces` device. The guest agent therefore exercises its full
//! cmdline-parse + ioctl path against an absent `eth0`: `SIOCSIFADDR` returns
//! `ENODEV`, and the agent must log the graceful `eth0 missing` line and keep
//! serving vsock (proving a broken/absent NIC never kills exec).
//!
//! This is the root-free proof of the ioctl path — no `sudo isopod setup`, no
//! tap. The real egress test happens after setup (see `docs/m4-verify.md`).
//!
//! Ignored by default; needs `/dev/kvm`, the FC binary, the CI kernel, and a
//! `dev-agent` rootfs built from the current agent:
//!
//! ```text
//! cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent
//! cargo run -p isopod-cli -- image build-rootfs --flavor dev-agent --force
//!
//! ISOPOD_FC_BIN=~/.isopod/bin/firecracker \
//! ISOPOD_FC_KERNEL=~/.isopod/images/vmlinux-6.18.36 \
//! ISOPOD_AGENT_ROOTFS=~/.isopod/images/rootfs-dev-agent.ext4 \
//!   cargo test -p isopod-guest-agent --test live_net -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use isopod_fc::models::{BootSource, Drive, MachineConfig, Vsock};
use isopod_fc::vsock::connect_to_guest;
use isopod_fc::{FcProcess, FcProcessConfig, StdioMode, VmId};
use isopod_proto::frame::aio::{read_frame, write_frame};
use isopod_proto::{Request, RequestOp, Response, VSOCK_PORT};
use tokio::io::AsyncReadExt;

/// Optimized boot args plus the static net config — but the test attaches **no**
/// NIC, so the guest's `eth0` is absent.
const BOOT_ARGS_NET: &str =
    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init quiet \
     i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1 \
     isopod.net=10.107.0.2/30 isopod.gw=10.107.0.1 isopod.dns=1.1.1.1,8.8.8.8";

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

#[tokio::test]
#[ignore = "requires ISOPOD_FC_BIN/KERNEL, a dev-agent ISOPOD_AGENT_ROOTFS, and /dev/kvm"]
async fn live_net_no_nic_degrades_gracefully() {
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

    let work = tempfile::tempdir().expect("tempdir");
    let base = work.path();
    let rootfs = base.join("rootfs.ext4");
    std::fs::copy(&rootfs_src, &rootfs).expect("copy rootfs");
    let api_sock = base.join("api.sock");
    let vsock_uds = base.join("vsock.sock");

    // Pipe the guest serial so we can assert on the agent's log lines.
    let mut proc = FcProcess::spawn(
        FcProcessConfig::new(&fc_bin, &api_sock)
            .id(VmId::new("isopod-net-live").expect("valid id"))
            .stdio(StdioMode::Piped)
            .socket_timeout(Duration::from_secs(10)),
    )
    .await
    .expect("spawn firecracker");

    let serial = Arc::new(Mutex::new(String::new()));
    if let Some(stdout) = proc.child_mut().stdout.take() {
        let sink = Arc::clone(&serial);
        tokio::spawn(async move {
            let mut rd = stdout;
            let mut buf = [0u8; 4096];
            while let Ok(n) = rd.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
                eprint!("{chunk}");
                sink.lock().unwrap().push_str(&chunk);
            }
        });
    }

    let client = proc.client().expect("client");
    client
        .put_machine_config(&MachineConfig::new(1, 256))
        .await
        .expect("machine-config");
    client
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), BOOT_ARGS_NET))
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
    // NOTE: deliberately NO put_network_interface — eth0 will be absent.
    client
        .put_vsock(&Vsock::new(3, vsock_uds.to_string_lossy()))
        .await
        .expect("vsock");
    client.instance_start().await.expect("InstanceStart");

    // The agent applies net config before the vsock server starts, so once Ping
    // answers, the "eth0 missing" line is already on the serial log.
    let answered = wait_for_agent(&vsock_uds, Duration::from_secs(20)).await;
    assert!(
        answered,
        "agent never answered Ping — exec must survive a missing NIC"
    );
    // Give the serial pipe a beat to flush the final lines.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _ = proc.shutdown(Duration::from_secs(3)).await;

    let log = serial.lock().unwrap().clone();
    let line = log
        .lines()
        .find(|l| l.contains("eth0 missing"))
        .unwrap_or("<not found>");
    eprintln!("\n==== ASSERTED SERIAL LINE ====\n{line}\n==============================");
    assert!(
        log.contains("eth0 missing"),
        "expected the agent to log 'eth0 missing' on a no-NIC boot; serial was:\n{log}"
    );
}

/// Poll `Ping` until the agent answers or the deadline passes.
async fn wait_for_agent(uds: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(mut s) = connect_to_guest(uds, VSOCK_PORT).await {
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
                if let Ok(Some(_resp)) = read_frame::<_, Response>(&mut s).await {
                    return true;
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
