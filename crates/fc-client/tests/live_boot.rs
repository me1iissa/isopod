//! Live integration test: boot a real Firecracker microVM and round-trip a
//! snapshot, driven entirely through `isopod-fc`.
//!
//! Ignored by default. Enable by setting all three artifact env vars and
//! running with `--ignored`:
//!
//! ```text
//! ISOPOD_FC_BIN=~/.isopod/m0/bin/firecracker \
//! ISOPOD_FC_KERNEL=~/.isopod/m0/images/vmlinux-6.18.36 \
//! ISOPOD_FC_ROOTFS=~/.isopod/m0/images/rootfs.ext4 \
//!   cargo test -p isopod-fc -- --ignored --nocapture
//! ```
//!
//! The rootfs pointed to by `ISOPOD_FC_ROOTFS` is copied to a scratch file
//! before booting — the original is never attached (a boot can dirty it).
//! Every Firecracker process is torn down via [`FcProcess`]'s `Drop` guard, so
//! a panic mid-test still leaves no leaked VMM.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use isopod_fc::models::{
    BootSource, Drive, MachineConfig, SnapshotCreateParams, SnapshotLoadParams,
};
use isopod_fc::{FcClient, FcProcess, FcProcessConfig, StdioMode, VmId};

/// Exact optimized boot args from the M0 recipe (NOTES-boot.md): `quiet` plus
/// the i8042 keyboard-probe disables that reclaim ~440 ms of cold boot.
const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init quiet \
     i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1";

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

/// Polls `GET /` until the instance reports `Running`, or the deadline passes.
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

#[tokio::test]
#[ignore = "requires ISOPOD_FC_BIN/KERNEL/ROOTFS and /dev/kvm"]
async fn live_boot_and_snapshot_round_trip() {
    let (Some(fc_bin), Some(kernel), Some(rootfs_src)) = (
        env_path("ISOPOD_FC_BIN"),
        env_path("ISOPOD_FC_KERNEL"),
        env_path("ISOPOD_FC_ROOTFS"),
    ) else {
        eprintln!(
            "SKIP: set ISOPOD_FC_BIN, ISOPOD_FC_KERNEL and ISOPOD_FC_ROOTFS to run this test"
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

    // Boot from a private copy so the source rootfs is never dirtied.
    let rootfs = base.join("rootfs.ext4");
    std::fs::copy(&rootfs_src, &rootfs).expect("copy rootfs");

    let sock1 = base.join("api1.sock");
    let snap_state = base.join("vm.state");
    let snap_mem = base.join("vm.mem");

    // ---- phase 1: cold boot -------------------------------------------------
    let t_spawn = Instant::now();
    let mut proc1 = FcProcess::spawn(
        FcProcessConfig::new(&fc_bin, &sock1)
            .id(VmId::new("isopod-live-1").expect("valid id"))
            .stdio(StdioMode::Null)
            .socket_timeout(Duration::from_secs(10)),
    )
    .await
    .expect("spawn firecracker #1");
    let socket_ready_ms = t_spawn.elapsed().as_secs_f64() * 1000.0;

    let client1 = proc1.client().expect("client #1");

    // Verify version negotiation works over the socket before configuring.
    let version = client1.get_version().await.expect("get version");
    assert_eq!(version.firecracker_version, isopod_fc::FIRECRACKER_VERSION);

    client1
        .put_machine_config(&MachineConfig::new(1, 256))
        .await
        .expect("machine-config");
    client1
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), BOOT_ARGS))
        .await
        .expect("boot-source");
    client1
        .put_drive(&Drive::virtio(
            "rootfs",
            rootfs.to_string_lossy(),
            true,
            true,
        ))
        .await
        .expect("drive");

    let t_boot = Instant::now();
    client1.instance_start().await.expect("InstanceStart");
    assert!(
        wait_running(&client1, Duration::from_secs(10)).await,
        "guest never reached Running after boot"
    );
    let boot_to_running_ms = t_boot.elapsed().as_secs_f64() * 1000.0;

    // ---- phase 2: pause + snapshot -----------------------------------------
    client1.pause().await.expect("pause");
    let t_snap = Instant::now();
    client1
        .create_snapshot(&SnapshotCreateParams::full(
            snap_state.to_string_lossy(),
            snap_mem.to_string_lossy(),
        ))
        .await
        .expect("create snapshot");
    let snapshot_create_ms = t_snap.elapsed().as_secs_f64() * 1000.0;
    assert!(
        snap_state.exists() && snap_mem.exists(),
        "snapshot files written"
    );

    // A snapshot load requires a pristine process; kill the source VM.
    proc1
        .shutdown(Duration::from_secs(2))
        .await
        .expect("shutdown #1");

    // ---- phase 3: restore into a fresh process -----------------------------
    let sock2 = base.join("api2.sock");
    let mut proc2 = FcProcess::spawn(
        FcProcessConfig::new(&fc_bin, &sock2)
            .id(VmId::new("isopod-live-2").expect("valid id"))
            .stdio(StdioMode::Null)
            .socket_timeout(Duration::from_secs(10)),
    )
    .await
    .expect("spawn firecracker #2");

    let client2 = proc2.client().expect("client #2");
    let t_restore = Instant::now();
    client2
        .load_snapshot(&SnapshotLoadParams::file_backed(
            snap_state.to_string_lossy(),
            snap_mem.to_string_lossy(),
            true,
        ))
        .await
        .expect("load snapshot");
    let load_return_ms = t_restore.elapsed().as_secs_f64() * 1000.0;

    assert!(
        wait_running(&client2, Duration::from_secs(10)).await,
        "restored guest never reported Running"
    );

    let restored = client2
        .get_instance_info()
        .await
        .expect("info after restore");
    assert!(restored.state.is_running(), "restored VM should be Running");

    proc2
        .shutdown(Duration::from_secs(2))
        .await
        .expect("shutdown #2");

    eprintln!(
        "LIVE OK: socket_ready={socket_ready_ms:.1}ms boot->running={boot_to_running_ms:.1}ms \
         snapshot_create={snapshot_create_ms:.1}ms snapshot_load_return={load_return_ms:.1}ms"
    );
}
