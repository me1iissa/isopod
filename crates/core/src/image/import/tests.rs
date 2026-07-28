//! Tests for the adaptation and the pack.
//!
//! The rule the extractor's suite is written under applies here too: for every
//! branch, construct the neighbouring input the obvious test misses. The
//! shell check gets a dangling link as well as a live one; the pseudo-file
//! encoder gets the names that are legal in a tar and hostile in a
//! space-delimited format.

use super::*;

/// A stand-in for the guest agent: the adaptation copies a file and marks it
/// executable, and none of that needs a real ELF.
fn fake_agent(dir: &Path) -> PathBuf {
    let p = dir.join("agent");
    std::fs::write(&p, b"\x7fELF stand-in").expect("write");
    p
}

/// The real static musl guest agent, which the two packing tests need.
///
/// The publish step verifies the binary is a static x86_64 ELF, so the
/// stand-in above will not do — and `ISOPOD_GUEST_AGENT_BIN` is process-global,
/// so setting it here made these two tests race each other and pass for the
/// wrong reason. `locate_guest_agent` finds this same path on its own; the
/// tests just need to hand the real thing to `adapt`.
fn real_agent() -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/isopod-guest-agent");
    assert!(
        p.exists(),
        "these tests need the musl guest agent: cargo build --release \
         --target x86_64-unknown-linux-musl -p isopod-guest-agent"
    );
    p
}

/// The minimum an image must ship to be adaptable.
fn minimal_image(root: &Path) {
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");
    std::fs::write(root.join("bin/sh"), b"#!/bin/sh\n").expect("write");
}

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p)
        .unwrap_or_else(|e| panic!("stat {}: {e}", p.display()))
        .permissions()
        .mode()
        & 0o7777
}

// --- the pseudo-file encoder --------------------------------------------

#[test]
fn a_pseudo_line_quotes_and_escapes_every_name() {
    // Measured against mksquashfs 4.6.1: inside a quoted name, a backslash is
    // written `\\` and a double quote `\"`. Everything else goes through
    // verbatim, including spaces and `#`.
    assert_eq!(pseudo_line("bin/su", 0o4755), "\"bin/su\" m 4755 0 0\n");
    assert_eq!(
        pseudo_line("has space", 0o4755),
        "\"has space\" m 4755 0 0\n"
    );
    assert_eq!(pseudo_line("#hash", 0o2755), "\"#hash\" m 2755 0 0\n");
    assert_eq!(
        pseudo_line(r#"a"b\c d"#, 0o1777),
        "\"a\\\"b\\\\c d\" m 1777 0 0\n"
    );
}

#[test]
fn a_name_that_forges_a_pseudo_definition_stays_one_field() {
    // The attack the quoting exists for. A tar entry named
    // `evil c 0666 0 0 1 3` renders, unquoted, as a line that reads "create a
    // character device" — and device nodes are the one thing the extractor
    // refuses to create. Quoted, the whole thing is a filename.
    let line = pseudo_line("evil c 0666 0 0 1 3", 0o4755);
    assert_eq!(line, "\"evil c 0666 0 0 1 3\" m 4755 0 0\n");
    // One field, and it is the name: everything after the closing quote is the
    // encoder's own four tokens.
    let (name, rest) = line
        .strip_prefix('"')
        .and_then(|l| l.split_once("\" "))
        .expect("the name is quoted");
    assert_eq!(name, "evil c 0666 0 0 1 3");
    assert_eq!(rest.trim_end(), "m 4755 0 0");
}

#[test]
fn a_pseudo_file_ends_every_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let modes = vec![("bin/su".to_string(), 0o4755), ("tmp".to_string(), 0o1777)];
    let p = write_pseudo_file(dir.path(), &modes).expect("writes");
    let text = std::fs::read_to_string(p).expect("read");
    assert_eq!(text, "\"bin/su\" m 4755 0 0\n\"tmp\" m 1777 0 0\n");
}

// --- the name that becomes a path ---------------------------------------

#[test]
fn a_slug_may_not_name_anything_outside_the_imports_directory() {
    let images = Path::new("/x/images");
    assert_eq!(
        imported_image_path(images, "alpine-3.20").expect("valid"),
        images.join("oci").join("alpine-3.20.sqfs")
    );
    for bad in [
        "",
        "..",
        "../escape",
        "a/b",
        ".hidden",
        "-leading",
        "has space",
        "semi;colon",
        "nul\0byte",
        "uni\u{00e9}code",
    ] {
        assert!(
            imported_image_path(images, bad).is_err(),
            "{bad:?} was accepted as an image name"
        );
    }
    // Neighbours that must still be accepted: the punctuation a real tag uses.
    for good in ["alpine-3.20", "python_3.12", "a", "ghcr.io-org-app-v1.2.3"] {
        assert!(
            imported_image_path(images, good).is_ok(),
            "{good:?} was refused"
        );
    }
}

// --- resolving inside the tree ------------------------------------------

#[test]
fn the_shell_check_resolves_against_the_image_and_not_the_host() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path();
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");

    // A plain file.
    std::fs::write(root.join("bin/sh"), b"x").expect("write");
    assert!(resolve_in_tree(root, "bin/sh").is_some());

    // An ABSOLUTE link to a path that exists on the host but not in the image.
    // `Path::exists()` would follow it to the host's /bin/sh and say yes; this
    // is the case that would let a distroless image past the check.
    std::fs::remove_file(root.join("bin/sh")).expect("rm");
    std::os::unix::fs::symlink("/bin/sh", root.join("bin/sh")).expect("symlink");
    assert!(
        Path::new("/bin/sh").exists(),
        "this test is only meaningful on a host that has /bin/sh"
    );
    assert!(
        resolve_in_tree(root, "bin/sh").is_none(),
        "an absolute link was resolved against the host"
    );

    // The same link, with the target present *in the image*.
    std::fs::write(root.join("bin/busybox"), b"x").expect("write");
    std::fs::remove_file(root.join("bin/sh")).expect("rm");
    std::os::unix::fs::symlink("/bin/busybox", root.join("bin/sh")).expect("symlink");
    assert!(resolve_in_tree(root, "bin/sh").is_some());

    // A relative link, which is how a usrmerge image spells it.
    std::fs::remove_file(root.join("bin/sh")).expect("rm");
    std::os::unix::fs::symlink("busybox", root.join("bin/sh")).expect("symlink");
    assert!(resolve_in_tree(root, "bin/sh").is_some());
}

#[test]
fn a_link_that_resolves_to_nothing_is_absent_rather_than_an_error() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path();
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");

    // Dangling.
    std::os::unix::fs::symlink("nowhere", root.join("bin/sh")).expect("symlink");
    assert!(resolve_in_tree(root, "bin/sh").is_none());

    // Self-referential: bounded, not detected, and the answer is still "no".
    std::fs::remove_file(root.join("bin/sh")).expect("rm");
    std::os::unix::fs::symlink("sh", root.join("bin/sh")).expect("symlink");
    assert!(resolve_in_tree(root, "bin/sh").is_none());

    // A pair that point at each other.
    std::fs::remove_file(root.join("bin/sh")).expect("rm");
    std::os::unix::fs::symlink("ash", root.join("bin/sh")).expect("symlink");
    std::os::unix::fs::symlink("sh", root.join("bin/ash")).expect("symlink");
    assert!(resolve_in_tree(root, "bin/sh").is_none());
}

#[test]
fn a_dotdot_in_the_image_is_clamped_at_its_own_root() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path();
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");
    std::fs::write(root.join("marker"), b"in the image").expect("write");
    // A link aimed above the image root resolves inside it, exactly as it would
    // once the image is mounted as `/`.
    std::os::unix::fs::symlink("../../../../marker", root.join("bin/sh")).expect("symlink");
    let got = resolve_in_tree(root, "bin/sh").expect("resolves");
    assert_eq!(got, root.join("marker"));
}

// --- the adaptation itself ----------------------------------------------

#[test]
fn an_image_without_a_shell_is_refused_by_name() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");
    let agent = fake_agent(t.path());
    let err = adapt(&root, &agent).expect_err("distroless must be refused");
    let msg = err.to_string();
    assert!(msg.contains("/bin/sh"), "{msg}");
    assert!(msg.contains("Distroless"), "{msg}");
    // The refusal names a way forward, not just a fault.
    assert!(msg.contains("alpine"), "{msg}");
}

#[test]
fn the_adaptation_adds_exactly_what_the_agent_needs() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(&root).expect("mkdir");
    minimal_image(&root);
    let agent = fake_agent(t.path());

    let rep = adapt(&root, &agent).expect("adapts");

    // The three overlay mountpoints, empty.
    for dir in OVERLAY_DIRS {
        let p = root.join(dir);
        assert!(p.is_dir(), "/{dir} missing");
        assert_eq!(mode_of(&p), DIR_MODE, "/{dir} mode");
        assert_eq!(
            std::fs::read_dir(&p).expect("readdir").count(),
            0,
            "/{dir} must be empty: preallocating /layers/<i> once capped a \
             chain at nine layers"
        );
    }
    // `/rom` is not created. It was read by nothing and removed in 0.12.0.
    assert!(!root.join("rom").exists(), "/rom must not be created");

    // The agent is installed where the design says, and `/init` points at it
    // relatively so it resolves against the image's root.
    assert_eq!(mode_of(&root.join(AGENT_PATH)), 0o755);
    assert_eq!(
        std::fs::read_link(root.join("init")).expect("read_link"),
        Path::new(AGENT_PATH)
    );
    assert!(!rep.replaced_init);

    // The image's own /sbin/init is not touched — on a Debian-derived image
    // that is systemd, and replacing it would be silent content mutation.
    assert!(!root.join("sbin/init").exists());

    assert!(rep.created_tmp, "the minimal image ships no /tmp");
    assert!(rep.dirs_created.contains(&"/overlay".to_string()));
    assert!(rep.dirs_created.contains(&"/tmp".to_string()));
}

#[test]
fn the_sticky_bit_for_a_created_tmp_never_touches_the_host() {
    // Invariant 6 extends to the directories the adaptation itself creates: the
    // sticky bit belongs in the image, applied by the pack step, and a 1777
    // directory in the operator's home is exactly what the extractor refuses to
    // produce.
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(&root).expect("mkdir");
    minimal_image(&root);
    let agent = fake_agent(t.path());
    let rep = adapt(&root, &agent).expect("adapts");
    assert!(rep.created_tmp);
    assert_eq!(
        mode_of(&root.join("tmp")) & 0o7000,
        0,
        "the sticky bit reached the host tree"
    );
    assert_eq!(mode_of(&root.join("tmp")), DIR_MODE);
}

#[test]
fn an_image_that_ships_its_own_init_has_it_replaced_and_recorded() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(&root).expect("mkdir");
    minimal_image(&root);
    std::fs::write(root.join("init"), b"the image's own init").expect("write");
    let agent = fake_agent(t.path());

    let rep = adapt(&root, &agent).expect("adapts");
    assert!(rep.replaced_init, "the replacement must be recorded");
    assert_eq!(
        std::fs::read_link(root.join("init")).expect("read_link"),
        Path::new(AGENT_PATH)
    );

    // Neighbour: an /init that is a SYMLINK rather than a file. `remove_file`
    // handles both, but a `copy` through the link would have written to its
    // target instead — which for `/init -> /sbin/init` means overwriting the
    // image's real init.
    let root2 = t.path().join("rootfs2");
    std::fs::create_dir_all(root2.join("sbin")).expect("mkdir");
    minimal_image(&root2);
    std::fs::write(root2.join("sbin/init"), b"systemd").expect("write");
    std::os::unix::fs::symlink("sbin/init", root2.join("init")).expect("symlink");
    let rep = adapt(&root2, &agent).expect("adapts");
    assert!(rep.replaced_init);
    assert_eq!(
        std::fs::read(root2.join("sbin/init")).expect("read"),
        b"systemd",
        "the image's real init was written through the link"
    );
}

#[test]
fn an_existing_directory_keeps_its_own_mode() {
    // The adaptation creates what is missing; it does not normalise what is
    // there. An image that ships a 0700 /var has reasons.
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(root.join("var")).expect("mkdir");
    minimal_image(&root);
    std::fs::set_permissions(root.join("var"), std::fs::Permissions::from_mode(0o700))
        .expect("chmod");
    let agent = fake_agent(t.path());
    let rep = adapt(&root, &agent).expect("adapts");
    assert_eq!(mode_of(&root.join("var")), 0o700);
    assert!(!rep.dirs_created.contains(&"/var".to_string()));
}

#[test]
fn a_symlinked_mountpoint_is_left_alone() {
    // usrmerge images point directories at other directories. Replacing one
    // with a fresh empty directory would be a silent content mutation, and for
    // `/var/run -> /run` a destructive one.
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(root.join("realvar")).expect("mkdir");
    minimal_image(&root);
    std::os::unix::fs::symlink("realvar", root.join("var")).expect("symlink");
    let agent = fake_agent(t.path());
    let rep = adapt(&root, &agent).expect("adapts");
    assert!(
        std::fs::symlink_metadata(root.join("var"))
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the link was replaced by a directory"
    );
    assert!(!rep.dirs_created.contains(&"/var".to_string()));
}

#[test]
fn a_file_where_a_mountpoint_must_go_is_refused() {
    let t = tempfile::tempdir().expect("tempdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(&root).expect("mkdir");
    minimal_image(&root);
    std::fs::write(root.join("proc"), b"not a directory").expect("write");
    let agent = fake_agent(t.path());
    let err = adapt(&root, &agent).expect_err("must refuse");
    assert!(err.to_string().contains("/proc"), "{err}");
}

// --- the whole pack, which needs squashfs-tools --------------------------

/// The end-to-end proof that the recorded bits land inside the image and
/// nowhere else. Needs `mksquashfs`/`unsquashfs`, which CI does not install:
///
/// ```text
/// cargo test -p isopod-core --lib -- --ignored import:: --nocapture
/// ```
#[test]
#[ignore = "requires squashfs-tools and a prebuilt guest-agent"]
fn the_recorded_bits_land_inside_the_image_and_nowhere_else() {
    let t = tempfile::tempdir().expect("tempdir");
    let images = t.path().join("images");
    std::fs::create_dir_all(&images).expect("mkdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(root.join("bin")).expect("mkdir");
    minimal_image(&root);

    // Two setuid binaries and one with a name that is hostile to the
    // pseudo-file format — the encoder's job, proved through the real packer.
    for name in ["bin/su", "bin/ping", "bin/evil c 0666 0 0 1 3"] {
        std::fs::write(root.join(name), b"ELF").expect("write");
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
    }
    let agent = real_agent();

    let modes: Vec<(String, u32)> = vec![
        ("bin/evil c 0666 0 0 1 3".to_string(), 0o4755),
        ("bin/ping".to_string(), 0o4711),
        ("bin/su".to_string(), 0o4755),
    ];
    let rep = adapt(&root, &agent).expect("adapts");
    assert!(rep.created_tmp);

    let spec = ImportSpec {
        slug: "test-image",
        special_modes: &modes,
        provenance: OciProvenance {
            source_ref: "alpine:3.20".into(),
            platform: "linux/amd64".into(),
            manifest_digest: "sha256:aa".into(),
            config_digest: "sha256:bb".into(),
            layer_digests: vec!["sha256:cc".into()],
            env: vec!["PATH=/usr/bin".into()],
            working_dir: Some("/srv".into()),
            entrypoint: vec!["/entry".into()],
            cmd: vec!["sh".into()],
            user: Some("nobody".into()),
            replaced_init: rep.replaced_init,
            setuid_paths: modes.iter().map(|(p, _)| p.clone()).collect(),
        },
    };
    let out = pack_and_stamp(&root, &images, &spec, rep).expect("packs");

    // Every recorded bit, plus the sticky /tmp the adaptation added.
    assert_eq!(out.adapt.special_modes, 4);
    assert_eq!(out.sha256.len(), 64);
    assert!(out.image_path.ends_with("oci/test-image.sqfs"));

    // Nothing setuid on the host tree, which is the whole point of recording
    // them rather than writing them.
    for (rel, _) in &modes {
        assert_eq!(mode_of(&root.join(rel)) & 0o7000, 0, "{rel} on the host");
    }
    assert_eq!(mode_of(&root.join("tmp")) & 0o7000, 0);

    // Inside the image, they are there.
    let listing = std::process::Command::new("unsquashfs")
        .arg("-ll")
        .arg(&out.image_path)
        .output()
        .expect("unsquashfs");
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("-rwsr-xr-x"), "{listing}");
    assert!(listing.contains("drwxrwxrwt"), "{listing}");
    assert!(
        listing.contains("evil c 0666 0 0 1 3"),
        "the hostile name did not survive the pseudo-file: {listing}"
    );

    // The sidecar carries the provenance, and it round-trips.
    let got = read_provenance(&out.image_path)
        .expect("reads")
        .expect("stamped");
    assert_eq!(got, spec.provenance);

    // The notices an operator has to see.
    assert!(
        out.notes.iter().any(|n| n.contains("USER")),
        "the ignored USER must be in the command's output: {:?}",
        out.notes
    );
    assert!(
        out.notes.iter().any(|n| n.contains("ENTRYPOINT")),
        "{:?}",
        out.notes
    );
}

/// The pack must not report success when a recorded mode did not land.
/// `mksquashfs` ignores a pseudo-file line it cannot place — silently, exit 0 —
/// so this is the only thing standing between a mis-encoded path and an image
/// whose `ping` quietly does not work.
#[test]
#[ignore = "requires squashfs-tools"]
fn a_mode_that_did_not_land_fails_the_pack() {
    let t = tempfile::tempdir().expect("tempdir");
    let images = t.path().join("images");
    std::fs::create_dir_all(&images).expect("mkdir");
    let root = t.path().join("rootfs");
    std::fs::create_dir_all(&root).expect("mkdir");
    minimal_image(&root);
    let agent = real_agent();
    let rep = adapt(&root, &agent).expect("adapts");

    // A path the tree does not have. The extractor cannot produce this, but a
    // future encoding bug presents exactly this way.
    let modes = vec![("bin/not-here".to_string(), 0o4755)];
    let spec = ImportSpec {
        slug: "missing-mode",
        special_modes: &modes,
        provenance: OciProvenance {
            source_ref: "x".into(),
            platform: "linux/amd64".into(),
            manifest_digest: "sha256:aa".into(),
            config_digest: "sha256:bb".into(),
            layer_digests: vec![],
            env: vec![],
            working_dir: None,
            entrypoint: vec![],
            cmd: vec![],
            user: None,
            replaced_init: false,
            setuid_paths: vec![],
        },
    };
    let err = pack_and_stamp(&root, &images, &spec, rep).expect_err("must fail");
    assert!(
        err.to_string().contains("did not apply every mode"),
        "{err}"
    );
}

// --- the three ways in --------------------------------------------------

#[test]
fn a_slug_derived_from_a_reference_is_usable_as_a_name() {
    assert_eq!(slug_for("alpine:3.20"), "alpine-3.20");
    assert_eq!(slug_for("ghcr.io/org/app:v1.2.3"), "ghcr.io-org-app-v1.2.3");
    assert_eq!(slug_for("python:3.12-slim"), "python-3.12-slim");
    // A digest reference: the separators collapse rather than becoming a row
    // of dashes.
    assert_eq!(slug_for("alpine@sha256:aabb"), "alpine-sha256-aabb");
    // A path, which is what --oci-layout and --docker-save describe.
    assert_eq!(slug_for("/var/tmp/my image.tar"), "var-tmp-my-image.tar");
    // Degenerate input still yields something the name rules accept.
    assert_eq!(slug_for("///"), "image");
    assert_eq!(slug_for(""), "image");

    // Whatever comes out must pass the guard the derivation is a convenience
    // for — otherwise a reference could produce a name the import then refuses.
    let images = Path::new("/x");
    for r in [
        "alpine:3.20",
        "ghcr.io/org/app:v1.2.3",
        "alpine@sha256:aabb",
        "/var/tmp/my image.tar",
        "///",
        "",
        "-leading-dash",
        "..",
        "../../etc/passwd",
    ] {
        let s = slug_for(r);
        assert!(
            imported_image_path(images, &s).is_ok(),
            "slug_for({r:?}) gave {s:?}, which the name rules refuse"
        );
    }
}

#[test]
fn a_legacy_docker_save_archive_is_refused_by_name() {
    let t = tempfile::tempdir().expect("tempdir");
    let dir = t.path().join("extracted");
    std::fs::create_dir_all(dir.join("abc123")).expect("mkdir");
    std::fs::write(
        dir.join("manifest.json"),
        br#"[{"Config":"c.json","Layers":["abc123/layer.tar"]}]"#,
    )
    .expect("write");

    let source = ImportSource::DockerSave(PathBuf::from("/tmp/saved.tar"));
    let err = open_layout(&dir, &source).expect_err("must refuse");
    let msg = format!("{err:#}");
    assert!(msg.contains("legacy"), "{msg}");
    // Named as the operator wrote it, not as the temporary directory it was
    // extracted into — which they have never seen.
    assert!(msg.contains("/tmp/saved.tar"), "{msg}");
    // And it says what to do instead.
    assert!(
        msg.contains("skopeo") || msg.contains("containerd"),
        "{msg}"
    );

    // Neighbour: the same directory once it IS an OCI layout is not caught by
    // the legacy branch. (It still fails — there is no index.json — but with
    // the layout reader's own message, not the legacy one.)
    std::fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).expect("write");
    let err = open_layout(&dir, &source).expect_err("still not a layout");
    let msg = format!("{err:#}");
    assert!(!msg.contains("legacy"), "{msg}");
}

#[test]
fn a_failure_to_read_a_layout_is_explained_per_source() {
    let t = tempfile::tempdir().expect("tempdir");
    let dir = t.path().join("empty");
    std::fs::create_dir_all(&dir).expect("mkdir");

    // A pull that stopped early leaves exactly this, and resuming is the fix.
    let err =
        open_layout(&dir, &ImportSource::Registry("alpine:3.20".into())).expect_err("not a layout");
    assert!(format!("{err:#}").contains("interrupted pull"), "{err:#}");

    // A directory the operator named is not an interrupted anything.
    let err = open_layout(&dir, &ImportSource::OciLayout(dir.clone())).expect_err("not a layout");
    assert!(!format!("{err:#}").contains("interrupted pull"), "{err:#}");
}
