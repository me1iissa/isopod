//! The fixture matrix.
//!
//! The rule this suite is written under, learned the expensive way elsewhere in
//! this repository: **for every refusal branch, construct the neighbouring
//! input the obvious test misses.** The dangling symbolic link as well as the
//! live one, the non-empty directory as well as the file, the target that never
//! existed as well as the one that does. Three review passes in a row found the
//! same class of hole — a test that covered only the spelling that already
//! worked — so the tables below are deliberately wider than the bug reports
//! that motivated them.
//!
//! Every refusal assertion also checks invariant 9 (see [`Case::refused`]), so
//! "the tree was not promoted" is not one test that could be deleted but a
//! property of every refusal in the file.

use super::*;
use crate::fixture::{gzip, Layer};
use std::path::PathBuf;

// --- harness ------------------------------------------------------------

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn dest(&self) -> PathBuf {
        self.dir.path().join("rootfs")
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.dest().join(rel)
    }

    fn run(&self, layers: &[Vec<u8>]) -> Result<Report, Refusal> {
        self.run_with(Limits::default(), layers)
    }

    fn run_with(&self, limits: Limits, layers: &[Vec<u8>]) -> Result<Report, Refusal> {
        let mut u = Unpacker::create(&self.dest(), limits)?;
        for layer in layers {
            u.apply_layer(&layer[..])?;
        }
        u.finish()
    }

    /// Anything in the working directory besides the destination — a staging
    /// tree that outlived a refusal shows up here.
    fn strays(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|n| n != "rootfs")
            .collect()
    }

    fn refused(&self, layers: &[Vec<u8>]) -> Refusal {
        self.refused_with(Limits::default(), layers)
    }

    fn refused_with(&self, limits: Limits, layers: &[Vec<u8>]) -> Refusal {
        let err = self
            .run_with(limits, layers)
            .expect_err("this image must be refused");
        assert!(!self.dest().exists(), "a refusal promoted a tree: {err}");
        assert!(
            self.strays().is_empty(),
            "a refusal left a staging tree behind: {:?}",
            self.strays()
        );
        err
    }
}

fn mode_of(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(p)
        .unwrap_or_else(|e| panic!("stat {}: {e}", p.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn there(p: &std::path::Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

fn text(p: &std::path::Path) -> String {
    String::from_utf8(std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())))
        .expect("utf8")
}

// --- the fixtures themselves --------------------------------------------

#[test]
fn the_fixture_builder_writes_the_name_it_was_given() {
    // A fixture that stopped containing its attack would leave the whole matrix
    // asserting nothing, which is this project's recurring failure mode. The
    // awkward names go out through the builder and come back through the same
    // `tar` parser the extractor uses.
    let names: Vec<Vec<u8>> = vec![
        b"/etc/passwd".to_vec(),
        b"../../../.ssh/authorized_keys".to_vec(),
        b"foo/../../etc/passwd".to_vec(),
        b"a\nb".to_vec(),
        vec![0xff, 0xfe, b'x'],
        b"./ordinary".to_vec(),
    ];
    let mut l = Layer::new();
    for n in &names {
        l.raw_file(n, b"");
    }
    let bytes = l.done();
    let mut archive = tar::Archive::new(&bytes[..]);
    let got: Vec<Vec<u8>> = archive
        .entries()
        .expect("entries")
        .map(|e| e.expect("entry").path_bytes().into_owned())
        .collect();
    assert_eq!(
        got, names,
        "the builder did not preserve the names verbatim"
    );
}

#[test]
fn an_ordinary_image_unpacks_untouched() {
    // The positive control. A guard that refuses everything passes every escape
    // test in this file, so the matrix only means something next to an image
    // that has to go through — including the shapes real base images actually
    // contain: absolute symlink targets, hard links, and a later layer
    // overwriting an earlier one's file.
    let mut l1 = Layer::new();
    l1.dir("./", 0o755)
        .dir("./bin", 0o755)
        .dir("./etc", 0o755)
        .file("./bin/busybox", 0o755, b"ELF")
        .symlink("./bin/sh", "/bin/busybox")
        .file("./etc/passwd", 0o644, b"root:x:0:0\n");
    let mut l2 = Layer::new();
    l2.file("./etc/passwd", 0o644, b"root:x:0:0\napp:x:1:1\n")
        .hardlink("./bin/ash", "bin/busybox")
        .dir("./srv", 0o755)
        .file("./srv/app.py", 0o644, b"print(1)\n");

    let case = Case::new();
    let rep = case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert_eq!(text(&case.at("etc/passwd")), "root:x:0:0\napp:x:1:1\n");
    assert_eq!(text(&case.at("srv/app.py")), "print(1)\n");
    assert_eq!(mode_of(&case.at("bin/busybox")), 0o755);
    assert_eq!(
        std::fs::read_link(case.at("bin/sh")).expect("read_link"),
        std::path::Path::new("/bin/busybox"),
        "an absolute link target is stored verbatim: inside the image it \
         resolves against the image's own root"
    );
    assert_eq!(text(&case.at("bin/ash")), "ELF");
    assert_eq!(rep.setuid_paths, Vec::new());
    assert_eq!(rep.devices_skipped, Vec::<String>::new());
    assert_eq!(rep.bytes_written, 3 + 11 + 21 + 9);
    assert!(rep.entries_written >= 9, "{rep:?}");
    assert!(case.strays().is_empty(), "staging survived a success");
}

// --- traversal and absolute paths ---------------------------------------

#[test]
fn a_name_that_leaves_the_root_is_refused_end_to_end() {
    for name in [
        "../../../.ssh/authorized_keys",
        "foo/../../etc/passwd",
        "./a/./../../b",
    ] {
        let case = Case::new();
        let mut l = Layer::new();
        l.raw_file(name.as_bytes(), b"pwned");
        assert!(
            matches!(case.refused(&[l.done()]), Refusal::PathEscapesRoot { .. }),
            "{name} was not refused"
        );
    }
    let case = Case::new();
    let mut l = Layer::new();
    l.raw_file(b"/etc/passwd", b"pwned");
    let err = case.refused(&[l.done()]);
    assert!(matches!(err, Refusal::AbsolutePath { .. }), "{err}");
    assert!(
        err.to_string().contains("relative to the image root"),
        "{err}"
    );
}

// --- the cross-layer symlink, which is the whole point ------------------

#[test]
fn a_symlink_planted_by_an_earlier_layer_is_never_written_through() {
    // The escape this crate exists to stop. Layer 1 is a plain symbolic link;
    // layer 2 is a plain file with an in-root name. Only together are they an
    // overwrite of a host file, which is why neither can be caught by looking
    // at one layer.
    let outside = tempfile::tempdir().expect("tempdir");
    let victim = outside.path().join(".bashrc");
    std::fs::write(&victim, b"original").expect("write");

    let cases: Vec<(String, &str)> = vec![
        (
            outside.path().display().to_string(),
            "a live directory outside the tree",
        ),
        ("../..".into(), "a relative hop out of the tree"),
        (
            // The class that broke `hostio.rs`: `exists()` follows the link and
            // reports false, so every check written around `stat` skips it.
            // `O_NOFOLLOW` never looks at the target, so it cannot be fooled.
            outside.path().join("does-not-exist").display().to_string(),
            "a dangling target",
        ),
    ];

    for (target, label) in cases {
        for same_layer in [false, true] {
            let case = Case::new();
            let mut l1 = Layer::new();
            l1.symlink("./foo", &target);
            let layers = if same_layer {
                l1.file("./foo/.bashrc", 0o644, b"pwned");
                vec![l1.done()]
            } else {
                let mut l2 = Layer::new();
                l2.file("./foo/.bashrc", 0o644, b"pwned");
                vec![l1.done(), l2.done()]
            };
            let err = case.refused(&layers);
            match &err {
                Refusal::SymlinkEscape { entry, via } => {
                    assert_eq!(entry, "foo/.bashrc");
                    assert_eq!(via, "foo");
                }
                other => panic!("{label} (same_layer={same_layer}): got {other:?}"),
            }
            assert!(err.to_string().contains("symbolic link"), "{err}");
        }
    }
    assert_eq!(
        text(&victim),
        "original",
        "a layer wrote through the link to a file outside the tree"
    );
}

#[test]
fn a_symlink_that_points_at_itself_is_refused_rather_than_resolved() {
    // A resolving extractor has to bound this with a link-depth counter. A
    // non-following walk has no chain to count: the very first component is a
    // link, and that is already the answer. The refusal names the link, which
    // is what an operator needs, rather than a depth number that describes the
    // extractor's algorithm.
    for links in [vec![("./a", "a")], vec![("./a", "b"), ("./b", "a")]] {
        let case = Case::new();
        let mut l1 = Layer::new();
        for (name, target) in &links {
            l1.symlink(name, target);
        }
        let mut l2 = Layer::new();
        l2.file("./a/x", 0o644, b"pwned");
        assert!(
            matches!(
                case.refused(&[l1.done(), l2.done()]),
                Refusal::SymlinkEscape { .. }
            ),
            "a self-referential link chain was not refused"
        );
    }
}

#[test]
fn a_symlink_to_a_plain_file_is_refused_as_a_parent_too() {
    // The neighbouring input: `openat(O_DIRECTORY|O_NOFOLLOW)` answers ELOOP for
    // a link to a directory but the kernel could equally answer ENOTDIR for a
    // link to a file, and only one of those two paths through the code checks
    // the link explicitly. Both have to reach the same refusal.
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.file("./f", 0o644, b"plain").symlink("./l", "f");
    let mut l2 = Layer::new();
    l2.file("./l/x", 0o644, b"pwned");
    let err = case.refused(&[l1.done(), l2.done()]);
    assert!(
        matches!(&err, Refusal::SymlinkEscape { via, .. } if via == "l"),
        "{err:?}"
    );
}

// --- hard links ---------------------------------------------------------

#[test]
fn a_hard_link_cannot_name_anything_outside_the_tree() {
    // A hard link is a second name for an inode, so no amount of path checking
    // on the *link* says anything about what it points at. The target gets the
    // same walk as an entry name — invariant 4.
    for target in ["../../etc/shadow", "/etc/shadow", "a/../../etc/shadow"] {
        let case = Case::new();
        let mut l = Layer::new();
        l.hardlink("./link", target);
        let err = case.refused(&[l.done()]);
        assert!(
            matches!(err, Refusal::HardlinkEscape { .. }),
            "{target}: {err:?}"
        );
    }
    // And through a symbolic link an earlier layer planted, which no check on
    // the spelling of the target would catch.
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.symlink("./s", "/etc");
    let mut l2 = Layer::new();
    l2.hardlink("./link", "s/shadow");
    let err = case.refused(&[l1.done(), l2.done()]);
    assert!(matches!(err, Refusal::HardlinkEscape { .. }), "{err:?}");
}

#[test]
fn a_hard_link_to_a_missing_target_is_refused_not_silently_empty() {
    // The neighbour to the escape test: a target that is perfectly in-root but
    // was never shipped. Creating an empty file here would hand back an image
    // that boots and is missing a binary.
    let case = Case::new();
    let mut l = Layer::new();
    l.hardlink("./link", "usr/bin/never-shipped");
    let err = case.refused(&[l.done()]);
    assert!(
        matches!(&err, Refusal::Malformed { detail, .. } if detail.contains("no earlier entry")),
        "{err:?}"
    );
}

#[test]
fn a_hard_link_to_a_symbolic_link_links_the_link_and_not_its_target() {
    // The neighbouring input the fixture matrix does not list. The target's
    // *parent* chain being confined is not enough: if the final component is a
    // symbolic link and `linkat` is given `AT_SYMLINK_FOLLOW`, the new name is a
    // second name for the inode the link points at — a host file — and writing
    // through the image truncates it. No path check can see that afterwards,
    // which is the same reason `hostio.rs` refuses multiply-linked files.
    let outside = tempfile::tempdir().expect("tempdir");
    let victim = outside.path().join("precious");
    std::fs::write(&victim, b"original").expect("write");

    let case = Case::new();
    let mut l1 = Layer::new();
    l1.symlink("./s", &victim.display().to_string());
    let mut l2 = Layer::new();
    l2.hardlink("./alias", "s");
    case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert!(
        std::fs::symlink_metadata(case.at("alias"))
            .expect("stat alias")
            .file_type()
            .is_symlink(),
        "the hard link followed the symbolic link out of the tree"
    );
    use std::os::unix::fs::MetadataExt as _;
    assert_ne!(
        std::fs::symlink_metadata(case.at("alias")).unwrap().ino(),
        std::fs::metadata(&victim).unwrap().ino(),
        "the image shares an inode with a host file"
    );
    assert_eq!(text(&victim), "original");
}

#[test]
fn a_legitimate_hard_link_shares_content() {
    // The positive control for the guard above.
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .file("./usr/bin/busybox", 0o755, b"ELF");
    let mut l2 = Layer::new();
    l2.hardlink("./usr/bin/ls", "usr/bin/busybox")
        .hardlink("./usr/bin/cat", "./usr/bin/busybox");
    case.run(&[l1.done(), l2.done()]).expect("must unpack");
    assert_eq!(text(&case.at("usr/bin/ls")), "ELF");
    assert_eq!(text(&case.at("usr/bin/cat")), "ELF");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        std::fs::metadata(case.at("usr/bin/ls")).unwrap().ino(),
        std::fs::metadata(case.at("usr/bin/busybox")).unwrap().ino(),
        "a hard link must share the inode, not copy the bytes"
    );
}

// --- device nodes and modes ---------------------------------------------

#[test]
fn devices_and_fifos_are_skipped_and_reported() {
    let case = Case::new();
    let mut l = Layer::new();
    l.dir("./dev", 0o755)
        .node("./dev/null", tar::EntryType::Char)
        .node("./dev/sda", tar::EntryType::Block)
        .node("./dev/initctl", tar::EntryType::Fifo)
        .file("./dev/README", 0o644, b"x");
    let rep = case.run(&[l.done()]).expect("must unpack");
    assert_eq!(
        rep.devices_skipped,
        vec!["dev/null", "dev/sda", "dev/initctl"]
    );
    for skipped in ["dev/null", "dev/sda", "dev/initctl"] {
        assert!(!there(&case.at(skipped)), "{skipped} was created");
    }
    assert!(there(&case.at("dev/README")), "the layer still applied");
}

#[test]
fn setuid_setgid_and_sticky_are_recorded_and_never_written_to_the_host() {
    // Invariant 6, and decision 3 of the import design: container semantics are
    // preserved inside the image, but nothing setuid is ever materialised in
    // the operator's home directory on the way there. Real Debian-derived base
    // images carry fifteen or so of these, so this is not a hypothetical.
    let case = Case::new();
    let mut l = Layer::new();
    l.dir("./usr", 0o755)
        .dir("./usr/bin", 0o755)
        .file("./usr/bin/sudo", 0o4755, b"ELF")
        .file("./usr/bin/wall", 0o2755, b"ELF")
        .dir("./tmp", 0o1777)
        .file("./usr/bin/plain", 0o755, b"ELF");
    let rep = case.run(&[l.done()]).expect("must unpack");

    assert_eq!(mode_of(&case.at("usr/bin/sudo")), 0o755);
    assert_eq!(mode_of(&case.at("usr/bin/wall")), 0o755);
    assert_eq!(mode_of(&case.at("tmp")), 0o777);
    assert_eq!(
        rep.setuid_paths,
        vec![
            ("usr/bin/sudo".to_string(), 0o4755),
            ("usr/bin/wall".to_string(), 0o2755),
            ("tmp".to_string(), 0o1777),
        ],
        "the pack step needs every one of these, or the image loses them"
    );
}

#[test]
fn a_directory_that_denies_its_owner_write_is_still_built_into() {
    // A mode applied when the directory is created would lock this crate out of
    // its own tree, so restrictive directory modes wait for `finish`. The
    // neighbour that matters: a later layer relaxing the mode has to win, which
    // means the deferred entry must be dropped rather than reapplied at the end.
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./locked", 0o500)
        .file("./locked/a", 0o644, b"1")
        .dir("./relaxed-later", 0o500)
        .file("./relaxed-later/a", 0o644, b"1");
    let mut l2 = Layer::new();
    l2.file("./locked/b", 0o644, b"2")
        .dir("./relaxed-later", 0o755);
    case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert_eq!(mode_of(&case.at("locked")), 0o500);
    assert_eq!(mode_of(&case.at("relaxed-later")), 0o755);
    // Readable again only because the test says so; the point is that both
    // files landed while the recorded mode said they could not.
    std::fs::set_permissions(
        case.at("locked"),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .expect("chmod");
    assert_eq!(text(&case.at("locked/a")), "1");
    assert_eq!(text(&case.at("locked/b")), "2");
}

// --- limits -------------------------------------------------------------

#[test]
fn a_compression_bomb_costs_the_cap_and_not_a_byte_more() {
    let mut l = Layer::new();
    l.zeros("./big", 8 << 20);
    let gz = gzip(&l.done());
    assert!(
        gz.len() < 64 * 1024,
        "the fixture is not a bomb: {} bytes compressed",
        gz.len()
    );

    let case = Case::new();
    let cap = 64 * 1024;
    let limits = Limits {
        max_entry_bytes: cap,
        ..Limits::default()
    };
    let mut u = Unpacker::create(&case.dest(), limits).expect("create");
    let err = u
        .apply_layer(flate2::read::GzDecoder::new(&gz[..]))
        .expect_err("the bomb must be refused");
    match &err {
        Refusal::LimitExceeded {
            limit,
            cap: c,
            raise,
        } => {
            assert_eq!(*limit, "max_entry_bytes");
            assert_eq!(*c, cap);
            assert!(raise.contains("max_entry_bytes"), "{raise}");
        }
        other => panic!("{other:?}"),
    }
    // The counter is on the decompressed stream, so the declared size never
    // mattered — and the refusal landed before the byte that would cross it.
    let written = std::fs::metadata(u.staging_path().join("big"))
        .expect("staged file")
        .len();
    assert!(written <= cap, "{written} bytes written past a {cap} cap");
    drop(u);
    assert!(case.strays().is_empty(), "the bomb left a staging tree");
}

#[test]
fn the_cumulative_ceilings_are_cumulative() {
    // Per-layer ceilings would multiply by however many layers a manifest
    // declares, which is the attacker's free variable.
    let mut a = Layer::new();
    a.file("./a", 0o644, &vec![b'x'; 100_000]);
    let mut b = Layer::new();
    b.file("./b", 0o644, &vec![b'y'; 100_000]);
    let case = Case::new();
    let err = case.refused_with(
        Limits {
            max_total_bytes: 150_000,
            ..Limits::default()
        },
        &[a.done(), b.done()],
    );
    assert!(
        matches!(&err, Refusal::LimitExceeded { limit, .. } if *limit == "max_total_bytes"),
        "{err:?}"
    );

    let mut many = Layer::new();
    for i in 0..10 {
        many.file(&format!("./f{i}"), 0o644, b"");
    }
    let case = Case::new();
    let err = case.refused_with(
        Limits {
            max_entries: 5,
            ..Limits::default()
        },
        &[many.done()],
    );
    assert!(
        matches!(&err, Refusal::LimitExceeded { limit, cap, .. } if *limit == "max_entries" && *cap == 5),
        "{err:?}"
    );
    assert!(err.to_string().contains("Limits::max_entries"), "{err}");
}

// --- names --------------------------------------------------------------

#[test]
fn hostile_names_are_refused_end_to_end() {
    for (raw, want_control) in [
        (b"etc/pass\nwd".to_vec(), true),
        (b"etc/pass\rwd".to_vec(), true),
        (vec![b'e', 0xff, 0xfe], false),
    ] {
        let case = Case::new();
        let mut l = Layer::new();
        l.raw_file(&raw, b"x");
        let err = case.refused(&[l.done()]);
        if want_control {
            assert!(matches!(err, Refusal::ControlCharInName { .. }), "{err:?}");
        } else {
            assert!(matches!(err, Refusal::NonUtf8Name { .. }), "{err:?}");
        }
    }
}

#[test]
fn the_name_that_is_checked_is_the_name_that_would_be_written() {
    // A PAX `path=` record overrides the ustar name field, and the ustar field
    // is NUL-terminated — so a NUL in a name can only arrive this way, and an
    // extractor that validated one field while writing the other would be
    // checking a string it never uses. Both halves are asserted: the hostile
    // PAX name is refused, and a benign one is what actually lands.
    for (raw, want) in [
        (b"../../escape".to_vec(), "escape"),
        (b"/etc/passwd".to_vec(), "absolute"),
        (b"etc/pass\0wd".to_vec(), "control"),
    ] {
        let case = Case::new();
        let mut l = Layer::new();
        l.pax_path_file(&raw, b"pwned");
        let err = case.refused(&[l.done()]);
        match (&err, want) {
            (Refusal::PathEscapesRoot { .. }, "escape")
            | (Refusal::AbsolutePath { .. }, "absolute")
            | (Refusal::ControlCharInName { .. }, "control") => {}
            _ => panic!("{}: {err:?}", String::from_utf8_lossy(&raw)),
        }
    }

    let case = Case::new();
    let mut l = Layer::new();
    l.pax_path_file(b"./srv/from-pax", b"ok");
    case.run(&[l.done()]).expect("must unpack");
    assert_eq!(text(&case.at("srv/from-pax")), "ok");
    assert!(
        !there(&case.at("ustar-name-that-must-not-be-used")),
        "the extractor wrote the ustar name while checking the PAX one"
    );
}

#[test]
fn names_differing_only_in_case_stay_distinct() {
    // Documented hazard rather than a guard: on a case-folding filesystem the
    // second entry would silently overwrite the first, and an image would be
    // imported with content it does not contain. isopod's stage store is ext4
    // and its unpack destination is under `$ISOPOD_HOME`, so this test is also
    // the check that the destination filesystem is one where that cannot
    // happen — if it ever fails, the extractor is running somewhere it must not.
    let case = Case::new();
    let mut l = Layer::new();
    l.file("./A", 0o644, b"upper").file("./a", 0o644, b"lower");
    let rep = case.run(&[l.done()]).expect("must unpack");
    assert_eq!(rep.entries_written, 2);
    assert_eq!(
        (text(&case.at("A")), text(&case.at("a"))),
        ("upper".to_string(), "lower".to_string()),
        "the destination filesystem folded case and merged two distinct entries"
    );
}

// --- whiteouts ----------------------------------------------------------

#[test]
fn a_whiteout_deletes_its_target_and_leaves_no_marker() {
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./d", 0o755)
        .file("./d/secret", 0o600, b"token")
        .file("./keep", 0o644, b"keep");
    let mut l2 = Layer::new();
    l2.whiteout("./d/.wh.secret");
    let rep = case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert!(!there(&case.at("d/secret")), "the deleted file survived");
    assert!(
        !there(&case.at("d/.wh.secret")),
        "the marker itself was materialised, so the image contains a file the \
         author never wrote"
    );
    assert!(there(&case.at("keep")));
    assert_eq!(rep.whiteouts_applied, 1);
}

#[test]
fn a_whiteout_removes_a_whole_subtree_and_a_link_without_following_it() {
    // Two neighbours the file-shaped test misses: a non-empty directory, and a
    // symbolic link, where a recursive delete that followed links would reach
    // outside the tree entirely.
    let outside = tempfile::tempdir().expect("tempdir");
    let bystander = outside.path().join("keep-me");
    std::fs::write(&bystander, b"untouched").expect("write");

    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./tree", 0o755)
        .dir("./tree/sub", 0o755)
        .file("./tree/sub/deep", 0o644, b"x")
        .file("./tree/shallow", 0o644, b"y")
        .symlink("./link", &outside.path().display().to_string());
    let mut l2 = Layer::new();
    l2.whiteout("./.wh.tree").whiteout("./.wh.link");
    case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert!(!there(&case.at("tree")), "the subtree survived");
    assert!(!there(&case.at("link")));
    assert!(
        bystander.exists(),
        "the recursive delete followed a symbolic link out of the tree"
    );
}

#[test]
fn a_whiteout_target_cannot_name_a_directory_instead_of_something_in_it() {
    // Found by attacking this crate rather than by reading the design. A
    // whiteout target is the only name that reaches the delete walk without
    // going through the component loop, because it is produced by stripping
    // `.wh.` off a component rather than by splitting a path. `.wh...` therefore
    // asked for `unlinkat(dirfd, "..")` — and at the top of the tree, `..` from
    // the staging root is the caller's destination directory. The recursive
    // delete would have emptied it.
    let case = Case::new();
    let sibling = case.dir.path().join("must-survive");
    std::fs::write(&sibling, b"not yours").expect("write");

    for marker in ["./.wh...", "./.wh..", "./d/.wh...", "./d/.wh.."] {
        let mut l1 = Layer::new();
        l1.dir("./d", 0o755).file("./d/x", 0o644, b"x");
        let mut l2 = Layer::new();
        l2.whiteout(marker);
        let inner = Case::new();
        let err = inner
            .run(&[l1.done(), l2.done()])
            .expect_err("{marker} must be refused");
        assert!(
            matches!(
                err,
                Refusal::PathEscapesRoot { .. } | Refusal::Malformed { .. }
            ),
            "{marker}: {err:?}"
        );
    }
    assert_eq!(
        text(&sibling),
        "not yours",
        "a whiteout reached outside the staging tree"
    );
}

#[test]
fn a_whiteout_for_something_that_never_existed_is_a_no_op() {
    // Rebasing an image routinely leaves markers for files the new lower layers
    // never had. Erroring here would refuse legitimate images.
    let case = Case::new();
    let mut l = Layer::new();
    l.file("./present", 0o644, b"x")
        .whiteout("./.wh.absent")
        .whiteout("./never/existed/.wh.either");
    let rep = case.run(&[l.done()]).expect("must unpack");
    assert_eq!(rep.whiteouts_applied, 2);
    assert!(there(&case.at("present")));
    assert!(
        !there(&case.at("never")),
        "a delete instruction created a directory"
    );
}

#[test]
fn an_opaque_marker_empties_the_directory_whatever_order_it_arrives_in() {
    // The OCI layer specification requires the marker to be "applied first ...
    // regardless of the ordering in which the whiteout file was encountered".
    // A streaming extractor cannot rewind, so the rule is implemented as "keep
    // exactly what this layer wrote" — which gives the same answer either way,
    // and this test is what proves the two orders agree.
    for marker_first in [true, false] {
        let case = Case::new();
        let mut l1 = Layer::new();
        l1.dir("./d", 0o755)
            .file("./d/old", 0o644, b"lower")
            .dir("./d/olddir", 0o755)
            .file("./d/olddir/deep", 0o644, b"lower")
            .file("./outside-d", 0o644, b"lower");
        let mut l2 = Layer::new();
        if marker_first {
            l2.file("./d/.wh..wh..opq", 0o644, b"");
        }
        l2.file("./d/new", 0o644, b"upper")
            .file("./d/nested/fresh", 0o644, b"upper");
        if !marker_first {
            l2.file("./d/.wh..wh..opq", 0o644, b"");
        }
        let rep = case.run(&[l1.done(), l2.done()]).expect("must unpack");

        assert_eq!(rep.opaque_dirs_applied, 1);
        assert!(!there(&case.at("d/old")), "marker_first={marker_first}");
        assert!(!there(&case.at("d/olddir")), "marker_first={marker_first}");
        assert!(
            !there(&case.at("d/.wh..wh..opq")),
            "the marker itself was materialised"
        );
        assert_eq!(text(&case.at("d/new")), "upper");
        assert_eq!(text(&case.at("d/nested/fresh")), "upper");
        assert_eq!(
            text(&case.at("outside-d")),
            "lower",
            "the marker reached outside its own directory"
        );
    }
}

#[test]
fn an_opaque_marker_hides_lower_content_inside_a_directory_the_layer_reuses() {
    // The subtle one. The layer writes `d/sub/fresh`, so `d/sub` has to survive
    // the marker — but everything *else* under `d/sub` came from a lower layer
    // and is exactly what the marker hides. Keeping the whole subtree because
    // one file in it was rewritten is how a `RUN rm` of a secret ends up still
    // in the image.
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./d", 0o755)
        .dir("./d/sub", 0o755)
        .file("./d/sub/secret", 0o600, b"token")
        .file("./d/sub/other", 0o644, b"lower");
    let mut l2 = Layer::new();
    l2.file("./d/sub/fresh", 0o644, b"upper")
        .file("./d/.wh..wh..opq", 0o644, b"");
    case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert_eq!(text(&case.at("d/sub/fresh")), "upper");
    assert!(
        !there(&case.at("d/sub/secret")),
        "an opaque marker left a lower-layer file the author deleted"
    );
    assert!(!there(&case.at("d/sub/other")));
}

#[test]
fn a_later_layer_re_adds_a_file_after_an_opaque_marker() {
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.dir("./d", 0o755).file("./d/a", 0o644, b"lower");
    let mut l2 = Layer::new();
    l2.file("./d/.wh..wh..opq", 0o644, b"");
    let mut l3 = Layer::new();
    l3.file("./d/a", 0o644, b"re-added");
    case.run(&[l1.done(), l2.done(), l3.done()])
        .expect("must unpack");
    assert_eq!(text(&case.at("d/a")), "re-added");
}

// --- ordering and type changes ------------------------------------------

#[test]
fn a_later_layer_wins_every_type_change() {
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.file("./becomes-dir", 0o644, b"was a file")
        .dir("./becomes-link", 0o755)
        .file("./becomes-link/buried", 0o644, b"must vanish")
        .dir("./becomes-file", 0o755)
        .symlink("./becomes-dir2", "/etc")
        .file("./implicit-parent", 0o644, b"was a file");
    let mut l2 = Layer::new();
    l2.dir("./becomes-dir", 0o755)
        .file("./becomes-dir/now", 0o644, b"ok")
        .symlink("./becomes-link", "/elsewhere")
        .file("./becomes-file", 0o644, b"now a file")
        .dir("./becomes-dir2", 0o755)
        .file("./implicit-parent/child", 0o644, b"ok");
    case.run(&[l1.done(), l2.done()]).expect("must unpack");

    assert_eq!(text(&case.at("becomes-dir/now")), "ok");
    assert!(
        std::fs::symlink_metadata(case.at("becomes-link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "a directory was not replaced by a symbolic link"
    );
    assert!(
        !there(&case.at("becomes-link/buried")),
        "replacing a directory with a link left its subtree reachable"
    );
    assert_eq!(text(&case.at("becomes-file")), "now a file");
    assert!(std::fs::symlink_metadata(case.at("becomes-dir2"))
        .unwrap()
        .is_dir());
    // The implicit case: no directory entry for `implicit-parent` in layer 2,
    // only a file beneath it. The walk has to replace the lower layer's file
    // rather than write through it.
    assert_eq!(text(&case.at("implicit-parent/child")), "ok");
}

// --- refusal is total ---------------------------------------------------

#[test]
fn a_refusal_discards_everything_earlier_layers_wrote() {
    // Invariant 9. Two layers of perfectly good content, then one bad entry:
    // the destination must not exist at all, because a half-applied image that
    // looks plausible is worse than no image.
    let case = Case::new();
    let mut good = Layer::new();
    good.dir("./bin", 0o755)
        .file("./bin/busybox", 0o755, b"ELF")
        .file("./etc-passwd", 0o644, b"root");
    let mut bad = Layer::new();
    bad.file("./ok", 0o644, b"fine")
        .raw_file(b"../../escape", b"pwned");

    let err = case.refused(&[good.done(), bad.done()]);
    assert!(matches!(err, Refusal::PathEscapesRoot { .. }), "{err:?}");
    // `Case::refused` already asserts the destination and the staging tree are
    // gone; this states the consequence the caller actually cares about.
    assert!(!case.at("bin/busybox").exists());
    assert_eq!(std::fs::read_dir(case.dir.path()).unwrap().count(), 0);
}

#[test]
fn a_destination_that_already_exists_is_never_written_into() {
    let case = Case::new();
    std::fs::create_dir(case.dest()).expect("mkdir");
    std::fs::write(case.at("precious"), b"mine").expect("write");
    let err = Unpacker::create(&case.dest(), Limits::default()).expect_err("must refuse");
    assert!(matches!(err, Refusal::Io { .. }), "{err:?}");
    assert_eq!(text(&case.at("precious")), "mine");

    // And a *dangling* symbolic link at the destination, which `Path::exists`
    // reports as absent — the shape that has slipped past this project's
    // confinements twice before.
    let case = Case::new();
    std::os::unix::fs::symlink("/nonexistent/isopod", case.dest()).expect("symlink");
    assert!(!case.dest().exists(), "the fixture is not dangling");
    assert!(Unpacker::create(&case.dest(), Limits::default()).is_err());
}

// --- reporting ----------------------------------------------------------

#[test]
fn dropped_extended_attributes_are_counted_rather_than_lost_silently() {
    let case = Case::new();
    let mut l = Layer::new();
    l.file_with_xattrs(
        "./bin/ping",
        b"ELF",
        &[
            ("security.capability", "cap_net_raw"),
            ("user.note", "hello"),
        ],
    )
    .file("./bin/plain", 0o644, b"x");
    let rep = case.run(&[l.done()]).expect("must unpack");
    assert_eq!(
        rep.xattrs_dropped, 2,
        "the pack step has to be told what was lost"
    );
    assert_eq!(text(&case.at("bin/ping")), "ELF");
}

#[test]
fn the_running_total_sums_the_layers() {
    let case = Case::new();
    let mut l1 = Layer::new();
    l1.file("./a", 0o4755, b"12345");
    let mut l2 = Layer::new();
    l2.file("./b", 0o644, b"123").whiteout("./.wh.a");
    let mut u = Unpacker::create(&case.dest(), Limits::default()).expect("create");
    let first = u.apply_layer(&l1.done()[..]).expect("layer 1");
    let second = u.apply_layer(&l2.done()[..]).expect("layer 2");
    assert_eq!((first.entries_written, first.bytes_written), (1, 5));
    assert_eq!((second.entries_written, second.whiteouts_applied), (1, 1));
    let total = u.finish().expect("finish");
    assert_eq!(total.entries_written, 2);
    assert_eq!(total.bytes_written, 8);
    assert_eq!(total.whiteouts_applied, 1);
    assert_eq!(total.setuid_paths, vec![("a".to_string(), 0o4755)]);
}
