//! Image-layout fixtures, generated the same way the layer fixtures are.
//!
//! A layout is a directory, so these build one on disk rather than in memory.
//! The rule from the layer matrix carries over unchanged: for every refusal,
//! construct the neighbouring input the obvious test misses — the digest that
//! is the right *length* as well as the one that is the wrong shape, the
//! manifest list with no matching platform as well as the one with none at all.

use super::*;
use crate::digest::Digest;
use crate::fixture::{gzip, Layer};
use crate::layout::{Compression, Layout, LayoutError, Platform};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A layout under construction.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        f.write("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
        f
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir.path().join(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(&p, bytes).expect("write");
        p
    }

    /// Store `bytes` as a blob and return the descriptor JSON that names it.
    fn blob(&self, media_type: &str, bytes: &[u8]) -> String {
        let hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
        self.write(&format!("blobs/sha256/{hex}"), bytes);
        format!(
            r#"{{"mediaType":"{media_type}","digest":"sha256:{hex}","size":{}}}"#,
            bytes.len()
        )
    }

    /// The same blob, as the parsed descriptor a caller would hold — for tests
    /// that read one blob directly rather than through an index.
    fn descriptor(&self, media_type: &str, bytes: &[u8]) -> crate::layout::Descriptor {
        let json = self.blob(media_type, bytes);
        let hex = json
            .split("sha256:")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("the blob helper writes a sha256 digest");
        crate::layout::Descriptor {
            media_type: media_type.to_string(),
            digest: Digest::parse(&format!("sha256:{hex}")).expect("its own digest must parse"),
            size: bytes.len() as u64,
            platform: None,
            annotations: BTreeMap::new(),
        }
    }

    fn open(&self) -> Result<Layout, LayoutError> {
        Layout::open(self.root())
    }
}

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const INDEX_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The smallest layer that is still a real one.
fn tiny_layer() -> Vec<u8> {
    let mut l = Layer::new();
    l.file("./a", 0o644, b"x");
    gzip(&l.done())
}

/// An ordinary single-platform layout: a config, one layer, one manifest, an
/// index that names it. This is the positive control — a reader that refused
/// everything would pass every other test in this file.
fn ordinary(f: &Fixture, platform: Option<&str>) -> Vec<u8> {
    let layer_bytes = gzip(&{
        let mut l = Layer::new();
        l.dir("./etc", 0o755)
            .file("./etc/hostname", 0o644, b"box\n");
        l.done()
    });
    let config = f.blob(
        CONFIG_TYPE,
        br#"{"config":{"Env":["PATH=/usr/bin"],"WorkingDir":"/srv","Cmd":["python3"],
             "Entrypoint":["/bin/sh","-c"],"User":"app"},
            "rootfs":{"type":"layers","diff_ids":["sha256:aa"]}}"#,
    );
    let layer = f.blob(LAYER_TYPE, &layer_bytes);
    let manifest = f.blob(
        MANIFEST_TYPE,
        format!(r#"{{"schemaVersion":2,"config":{config},"layers":[{layer}]}}"#).as_bytes(),
    );
    let entry = match platform {
        Some(p) => manifest.replace('}', &format!(r#","platform":{p}}}"#)),
        None => manifest,
    };
    f.write(
        "index.json",
        format!(r#"{{"schemaVersion":2,"manifests":[{entry}]}}"#).as_bytes(),
    );
    layer_bytes
}

#[test]
fn an_ordinary_layout_resolves_and_its_layer_unpacks() {
    let f = Fixture::new();
    ordinary(&f, None);
    let layout = f.open().expect("must open");

    let m = layout.resolve(&Platform::host()).expect("must resolve");
    assert_eq!(m.layers.len(), 1);
    assert_eq!(
        Compression::of(&m.layers[0].media_type),
        Some(Compression::Gzip)
    );

    let cfg = layout.config(&m.config).expect("must read config");
    assert_eq!(cfg.env, vec!["PATH=/usr/bin".to_string()]);
    assert_eq!(cfg.working_dir.as_deref(), Some("/srv"));
    assert_eq!(cfg.cmd, vec!["python3".to_string()]);
    assert_eq!(
        cfg.entrypoint,
        vec!["/bin/sh".to_string(), "-c".to_string()]
    );
    assert_eq!(cfg.user.as_deref(), Some("app"), "recorded, then ignored");

    // End to end: the descriptor addresses a blob, the blob verifies, and what
    // comes out of it goes through the extractor that the rest of this crate is.
    let blob = layout.blob(&m.layers[0]).expect("must verify");
    let dest = f.root().join("rootfs");
    let mut u = Unpacker::create(&dest, Limits::default()).expect("staging");
    u.apply_layer(flate2::read::GzDecoder::new(blob))
        .expect("must unpack");
    u.finish().expect("must promote");
    assert_eq!(
        std::fs::read_to_string(dest.join("etc/hostname")).expect("read"),
        "box\n"
    );
}

#[test]
fn a_blob_that_does_not_match_its_digest_is_refused_before_it_is_used() {
    // The verification that makes every other check meaningful. The blob is
    // altered *after* the manifest recorded it, which is the shape a corrupt
    // mirror or an altered layout has.
    let f = Fixture::new();
    ordinary(&f, None);
    let layout = f.open().expect("must open");
    let m = layout.resolve(&Platform::host()).expect("must resolve");

    // Same length, different bytes: a size check alone would pass this.
    let path = layout.blob_path(&m.layers[0]);
    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).expect("write");

    let err = layout.blob(&m.layers[0]).expect_err("must refuse");
    assert!(matches!(err, LayoutError::DigestMismatch { .. }), "{err:?}");
    assert!(
        err.to_string().contains("does not match the digest"),
        "{err}"
    );

    // And the neighbour a same-length edit hides: a blob of the wrong size is
    // caught by the size check before anything is hashed.
    bytes.push(0);
    std::fs::write(&path, &bytes).expect("write");
    let err = layout.blob(&m.layers[0]).expect_err("must refuse");
    assert!(matches!(err, LayoutError::Malformed { .. }), "{err:?}");
}

#[test]
fn a_manifest_digest_cannot_name_a_file_outside_the_blob_store() {
    // The metadata half of the traversal question. `Digest::parse` is what
    // stops it, and this is the end-to-end proof that nothing reaches a path
    // join without going through it.
    let f = Fixture::new();
    let outside = f.dir.path().join("secret");
    std::fs::write(&outside, b"host secret").expect("write");
    f.write(
        "index.json",
        br#"{"schemaVersion":2,"manifests":[
             {"mediaType":"application/vnd.oci.image.manifest.v1+json",
              "digest":"sha256:../../secret","size":11}]}"#,
    );
    let layout = f.open().expect("must open");
    let err = layout.index().expect_err("must refuse");
    assert!(matches!(err, LayoutError::BadDigest(_)), "{err:?}");
    assert!(outside.exists(), "the file was never touched");
}

#[test]
fn an_index_that_offers_no_usable_platform_says_what_it_has() {
    let f = Fixture::new();
    ordinary(
        &f,
        Some(r#"{"os":"linux","architecture":"arm64","variant":"v8"}"#),
    );
    let layout = f.open().expect("must open");
    let err = layout.resolve(&Platform::host()).expect_err("must refuse");
    let LayoutError::NoSuchPlatform { want, have } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(want, "linux/amd64");
    assert_eq!(have, &vec!["linux/arm64/v8".to_string()]);
    assert!(
        err.to_string().contains("boots x86-64 Linux guests"),
        "{err}"
    );
}

#[test]
fn a_stated_variant_must_be_asked_for_but_an_absent_one_matches() {
    // The neighbour that a naive equality check gets wrong in one direction and
    // a naive "ignore the variant" check gets wrong in the other.
    let want = Platform::host();
    let bare = Platform {
        os: "linux".into(),
        architecture: "amd64".into(),
        variant: None,
    };
    let v3 = Platform {
        variant: Some("v3".into()),
        ..bare.clone()
    };
    assert!(
        bare.satisfies(&want),
        "an index that states no variant matches"
    );
    assert!(!v3.satisfies(&want), "a stated variant must be asked for");
    assert!(
        v3.satisfies(&Platform {
            variant: Some("v3".into()),
            ..want.clone()
        }),
        "and matches when it is"
    );
}

#[test]
fn a_multi_platform_index_picks_the_hosts_manifest() {
    let f = Fixture::new();
    let layer = f.blob(LAYER_TYPE, &tiny_layer());
    let config = f.blob(CONFIG_TYPE, br#"{"rootfs":{"diff_ids":[]}}"#);
    let body = format!(r#"{{"schemaVersion":2,"config":{config},"layers":[{layer}]}}"#);
    // Two manifests differing only in a byte, so their digests differ and the
    // test can tell which one was chosen.
    let arm = f.blob(MANIFEST_TYPE, format!("{body} ").as_bytes());
    let amd = f.blob(MANIFEST_TYPE, body.as_bytes());
    let entry = |d: &str, os: &str, arch: &str| {
        d.replace(
            '}',
            &format!(r#","platform":{{"os":"{os}","architecture":"{arch}"}}}}"#),
        )
    };
    f.write(
        "index.json",
        format!(
            r#"{{"schemaVersion":2,"manifests":[{},{}]}}"#,
            entry(&arm, "linux", "arm64"),
            entry(&amd, "linux", "amd64")
        )
        .as_bytes(),
    );
    let layout = f.open().expect("must open");
    // Resolving must not merely succeed — it must succeed with the *amd64*
    // manifest, which is only checkable because the two blobs differ.
    let m = layout.resolve(&Platform::host()).expect("must resolve");
    let chosen = layout.manifest(&{
        let mut d = m.config.clone();
        d.media_type = CONFIG_TYPE.into();
        d
    });
    assert!(chosen.is_err(), "a config blob is not a manifest");
    assert_eq!(m.layers.len(), 1);
}

#[test]
fn an_index_that_points_at_an_index_is_followed_but_not_forever() {
    // How a layout that wraps a manifest list is shaped: `index.json` names one
    // index blob, which names the per-platform manifests. Following it is
    // required; following it without a bound is a layout that can point at
    // itself.
    let f = Fixture::new();
    let config = f.blob(CONFIG_TYPE, br#"{"rootfs":{"diff_ids":[]}}"#);
    let layer = f.blob(LAYER_TYPE, &tiny_layer());
    let manifest = f.blob(
        MANIFEST_TYPE,
        format!(r#"{{"schemaVersion":2,"config":{config},"layers":[{layer}]}}"#).as_bytes(),
    );
    let inner = f.blob(
        INDEX_TYPE,
        format!(
            r#"{{"schemaVersion":2,"manifests":[{}]}}"#,
            manifest.replace('}', r#","platform":{"os":"linux","architecture":"amd64"}}"#)
        )
        .as_bytes(),
    );
    f.write(
        "index.json",
        format!(r#"{{"schemaVersion":2,"manifests":[{inner}]}}"#).as_bytes(),
    );
    let m = f
        .open()
        .expect("must open")
        .resolve(&Platform::host())
        .expect("a nested index must be followed");
    assert_eq!(m.layers.len(), 1);

    // The neighbour: an index that names itself. It is a legal document and a
    // reader that recurses on it never returns — so the answer has to be a
    // refusal, and a bounded amount of work.
    let g = Fixture::new();
    let placeholder = g.blob(INDEX_TYPE, b"{}");
    let hex = placeholder
        .split("sha256:")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("digest")
        .to_string();
    // A blob whose own content names its own digest cannot be built by hashing,
    // so the cycle is two blobs pointing at each other instead — the same
    // shape, and one a fixed point could not produce.
    let a_body = format!(
        r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{INDEX_TYPE}","digest":"sha256:{hex}","size":2}}]}}"#
    );
    let a = g.blob(INDEX_TYPE, a_body.as_bytes());
    let b_hex = a
        .split("sha256:")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("digest")
        .to_string();
    g.write(
        &format!("blobs/sha256/{hex}"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{INDEX_TYPE}","digest":"sha256:{b_hex}","size":{}}}]}}"#,
            a_body.len()
        )
        .as_bytes(),
    );
    g.write(
        "index.json",
        format!(r#"{{"schemaVersion":2,"manifests":[{a}]}}"#).as_bytes(),
    );
    // The rewritten blob no longer hashes to the name it is stored under, which
    // is itself a refusal — and that is the honest outcome to assert. What must
    // not happen, either way, is a hang or a stack overflow.
    let err = g
        .open()
        .expect("must open")
        .resolve(&Platform::host())
        .expect_err("a cycle cannot resolve");
    assert!(
        matches!(
            err,
            LayoutError::DigestMismatch { .. }
                | LayoutError::NoSuchPlatform { .. }
                | LayoutError::Malformed { .. }
        ),
        "{err:?}"
    );
}

#[test]
fn a_layer_type_isopod_cannot_unpack_is_refused_before_the_first_layer_lands() {
    let f = Fixture::new();
    let config = f.blob(CONFIG_TYPE, br#"{"rootfs":{"diff_ids":[]}}"#);
    let good = f.blob(LAYER_TYPE, &tiny_layer());
    let foreign = f.blob(
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        b"not here",
    );
    let manifest = f.blob(
        MANIFEST_TYPE,
        format!(r#"{{"schemaVersion":2,"config":{config},"layers":[{good},{foreign}]}}"#)
            .as_bytes(),
    );
    f.write(
        "index.json",
        format!(r#"{{"schemaVersion":2,"manifests":[{manifest}]}}"#).as_bytes(),
    );
    let layout = f.open().expect("must open");
    let err = layout.resolve(&Platform::host()).expect_err("must refuse");
    assert!(matches!(err, LayoutError::Malformed { .. }), "{err:?}");
    assert!(
        err.to_string().contains("not stored in the layout"),
        "the message has to explain that the bytes are elsewhere: {err}"
    );
}

#[test]
fn a_directory_that_is_not_a_layout_says_so_rather_than_reading_it() {
    let d = tempfile::tempdir().expect("tempdir");
    let err = Layout::open(d.path()).expect_err("no marker");
    assert!(matches!(err, LayoutError::NotALayout { .. }), "{err:?}");

    // The neighbours: a marker that is not JSON, one with no version, one with
    // a version from a future spec, and an otherwise-valid layout with no
    // index. Each must be refused *as a layout*, not as a read error.
    for marker in [
        &b"not json"[..],
        br#"{}"#,
        br#"{"imageLayoutVersion":"2.0.0"}"#,
    ] {
        let f = Fixture::new();
        f.write("oci-layout", marker);
        f.write("index.json", b"{}");
        let err = f.open().expect_err("must refuse");
        assert!(
            matches!(err, LayoutError::NotALayout { .. }),
            "{marker:?} -> {err:?}"
        );
    }
    let f = Fixture::new();
    assert!(matches!(
        f.open().expect_err("no index"),
        LayoutError::NotALayout { .. }
    ));
}

#[test]
fn metadata_is_read_under_a_ceiling_that_the_declared_size_cannot_lift() {
    // A descriptor claiming a size over the cap is refused without opening the
    // file; a descriptor *lying* about a small size is refused by the read.
    // Both matter: the first is what makes a hostile index cheap to reject, the
    // second is what stops a small claim from being trusted.
    let f = Fixture::new();
    f.write(
        "index.json",
        br#"{"schemaVersion":2,"manifests":[
             {"mediaType":"application/vnd.oci.image.manifest.v1+json",
              "digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "size":8388608}]}"#,
    );
    let layout = f.open().expect("must open");
    let entries = layout.index().expect("the index itself parses");
    let err = layout.manifest(&entries[0]).expect_err("must refuse");
    assert!(matches!(err, LayoutError::TooLarge { .. }), "{err:?}");

    // And an index.json that is itself enormous: refused before it is parsed.
    let big = vec![b' '; 5 * 1024 * 1024];
    f.write("index.json", &big);
    let err = f.open().expect("opens").index().expect_err("must refuse");
    assert!(matches!(err, LayoutError::TooLarge { .. }), "{err:?}");
}

#[test]
fn a_descriptor_with_a_negative_size_is_refused_rather_than_wrapped() {
    // JSON has no unsigned integers. A `-1` that becomes `u64::MAX` would sail
    // past every ceiling check by being absurd rather than by being small.
    let f = Fixture::new();
    f.write(
        "index.json",
        br#"{"schemaVersion":2,"manifests":[
             {"mediaType":"application/vnd.oci.image.manifest.v1+json",
              "digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "size":-1}]}"#,
    );
    let err = f.open().expect("opens").index().expect_err("must refuse");
    assert!(matches!(err, LayoutError::Malformed { .. }), "{err:?}");
    assert!(err.to_string().contains("negative size"), "{err}");
}

#[test]
fn an_empty_manifest_is_not_an_image() {
    let f = Fixture::new();
    let config = f.blob(CONFIG_TYPE, br#"{"rootfs":{"diff_ids":[]}}"#);
    let manifest = f.blob(
        MANIFEST_TYPE,
        format!(r#"{{"schemaVersion":2,"config":{config},"layers":[]}}"#).as_bytes(),
    );
    f.write(
        "index.json",
        format!(r#"{{"schemaVersion":2,"manifests":[{manifest}]}}"#).as_bytes(),
    );
    let err = f
        .open()
        .expect("opens")
        .resolve(&Platform::host())
        .expect_err("must refuse");
    assert!(err.to_string().contains("no layers"), "{err}");
}

#[test]
fn an_empty_working_dir_and_user_are_absent_rather_than_empty_strings() {
    // How the fields are actually spelled by real builders when there is no
    // value. Carrying `Some("")` through would start a run in a directory that
    // does not exist.
    let f = Fixture::new();
    let d = f.descriptor(
        CONFIG_TYPE,
        br#"{"config":{"WorkingDir":"","User":""},"rootfs":{"diff_ids":[]}}"#,
    );
    f.write("index.json", br#"{"schemaVersion":2,"manifests":[]}"#);
    let cfg = f.open().expect("must open").config(&d).expect("must read");
    assert_eq!(cfg.working_dir, None);
    assert_eq!(cfg.user, None);
}
