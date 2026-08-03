//! Live jail-launcher probe (ignored by default — needs unprivileged user
//! namespaces, which not every CI kernel grants).
//!
//! Runs the built `isopod-jail` binary against `/bin/sh`, proving the launcher
//! mechanics on the host *before* any Firecracker wiring:
//!
//! * the child sees in-namespace **uid 0** (single-id user-namespace map),
//! * a read-write bind is writable while the whole `/` is bound read-only
//!   (the exact "rw nested over ro home" pattern a real run uses),
//! * a **submount** of that read-only bind is read-only too — `/dev/shm`, a
//!   `nosuid,nodev` tmpfs under `/`, which also exercises the locked-flag rule,
//! * both implementations of that recursive remount: `mount_setattr(2)` on a
//!   5.12+ kernel and the mountinfo walk every older one falls back to,
//! * `/dev/kvm` is **openable read-write** inside the namespace (proof that the
//!   retained `kvm` supplementary group + the bound device node work together —
//!   no host `chmod`), and
//! * the launcher exits `0`, proxying the child's status.
//!
//! `--cgroup` is deliberately omitted: cgroup *placement* requires running inside
//! the systemd user-session's delegated subtree (validated live by the
//! coordinator), whereas these mechanics are testable anywhere userns is allowed.
//!
//! Run with: `cargo test -p isopod-jail -- --ignored`.

use std::path::Path;
use std::process::Command;

/// Whether unprivileged user namespaces look available on this host.
fn userns_available() -> bool {
    std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

/// Read the first (real) id from a `Uid:`/`Gid:` line of `/proc/self/status`.
/// The single-id user-namespace map must map in-namespace 0 to the writer's
/// *real* id, so the launcher must be handed these — not an arbitrary value.
fn real_id(prefix: &str) -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| {
            l.strip_prefix(prefix)
                .and_then(|r| r.split_whitespace().next())
        })
        .unwrap()
        .to_string()
}

#[test]
#[ignore = "needs unprivileged user namespaces; run with --ignored"]
fn jail_unshares_chroots_and_opens_kvm() {
    if !userns_available() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }

    let jail_bin = env!("CARGO_BIN_EXE_isopod-jail");

    // A throwaway chroot dir and a rw scratch dir, both under the target tmp dir
    // (on the main filesystem, so the rw bind nests over the read-only `/` bind
    // exactly like a real run's vm_dir nests under the read-only isopod home).
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let root = base.join(format!("jail-root-{}", std::process::id()));
    let scratch = base.join(format!("jail-scratch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    let out_file = scratch.join("out");

    // The child records: in-ns uid, whether /dev/kvm opens rw, and its CapEff.
    // The scratch path is identity-mapped, so it is the same absolute path inside
    // the chroot; the rw bind makes it writable over the read-only `/`.
    let script = format!(
        "id -u > {out}; \
         if : 9<>/dev/kvm; then echo KVM-RW-OK >> {out}; else echo KVM-RW-FAIL >> {out}; fi; \
         if ( : > /dev/shm/isopod-jail-hole ) 2>/dev/null; \
           then echo SHM-RW-HOLE >> {out}; else echo SHM-RO-OK >> {out}; fi; \
         grep CapEff /proc/self/status >> {out}; \
         echo DONE >> {out}",
        out = out_file.display()
    );

    let uid = real_id("Uid:");
    let gid = real_id("Gid:");

    // Both implementations of the recursive read-only remount, on every host
    // that can run this at all. `mount_setattr(2)` is what a 5.12+ kernel takes;
    // the mountinfo walk is what everything older takes, and without forcing it
    // here it would only ever run on machines nobody tests on.
    for force_walk in [false, true] {
        let _ = std::fs::remove_file(&out_file);
        let mut cmd = Command::new(jail_bin);
        cmd.args([
            "--root",
            root.to_str().unwrap(),
            "--uid",
            &uid, // in-ns 0 maps to the writer's real uid (single-id map)
            "--gid",
            &gid,
            "--bind",
            &format!("{}:ro", "/"),
            "--bind",
            &format!("{}:rw", scratch.display()),
            "--dev",
            "/dev/kvm",
            "--dev",
            "/dev/null",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ]);
        if force_walk {
            cmd.env("ISOPOD_JAIL_FORCE_REMOUNT_WALK", "1");
        }
        let status = cmd.status().expect("spawn isopod-jail");

        let how = if force_walk {
            "mountinfo walk"
        } else {
            "mount_setattr"
        };
        assert!(
            status.success(),
            "jail launcher exited non-zero via {how}: {status:?}"
        );

        let out = std::fs::read_to_string(&out_file).expect("child wrote the rw-bound output file");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some("0"),
            "child must see in-namespace uid 0 ({how}); got {out:?}"
        );
        assert!(
            out.contains("KVM-RW-OK"),
            "/dev/kvm must be openable rw inside the jail (retained kvm group + bound node) ({how}); got {out:?}"
        );
        // The regression this pair of paths exists for: a read-only bind is
        // recursive, so a *submount* of it is read-only too. `/dev/shm` is a
        // tmpfs under the read-only `/`, and it is `nosuid,nodev` — so it also
        // proves the walk hands those locked flags back, which is the difference
        // between a read-only submount and EPERM.
        if shm_is_a_writable_submount() {
            assert!(
                out.contains("SHM-RO-OK"),
                "a submount of a read-only bind must be read-only ({how}); got {out:?}"
            );
        }
        assert!(
            out.contains("CapEff"),
            "CapEff line present ({how}); got {out:?}"
        );
        assert!(
            out.contains("DONE"),
            "child ran to completion ({how}); got {out:?}"
        );
    }

    // Cleanup (best-effort; the chroot holds only empty mountpoint skeletons).
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&scratch);
}

/// Whether `/dev/shm` is a mount in its own right and writable here — the
/// precondition for the submount assertion above. Stated as a check rather than
/// assumed, so a host without it reports one fewer assertion instead of a
/// mysterious failure.
fn shm_is_a_writable_submount() -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|mi| {
            mi.lines()
                .filter_map(|l| l.split(' ').nth(4))
                .any(|mp| mp == "/dev/shm")
        })
        .unwrap_or(false)
        && {
            let probe = "/dev/shm/.isopod-jail-probe";
            let ok = std::fs::write(probe, b"x").is_ok();
            let _ = std::fs::remove_file(probe);
            ok
        }
}
