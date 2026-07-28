//! A fake registry, so the request loop is exercised rather than merely read.
//!
//! `auth.rs` decides *whether* a credential may travel and *whether* a redirect
//! may be followed, and those decisions are unit-tested there. What is only
//! testable here is that the loop in [`Puller::get`] actually asks: a policy
//! nothing calls is a policy that holds in the test suite and nowhere else.
//!
//! The registry is two `TcpListener`s on loopback speaking the smallest HTTP
//! that answers the question — no dependency, no fixture image, no network.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use super::*;

/// One request, as much of it as the assertions need.
struct Request {
    line: String,
    authorization: Option<String>,
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("request line");
    let mut authorization = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).expect("header") == 0 {
            break;
        }
        if header.trim().is_empty() {
            break;
        }
        if let Some(v) = header
            .strip_prefix("authorization: ")
            .or_else(|| header.strip_prefix("Authorization: "))
        {
            authorization = Some(v.trim().to_string());
        }
    }
    Request {
        line: line.trim().to_string(),
        authorization,
    }
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &[u8]) {
    let mut out = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n", body.len());
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("connection: close\r\n\r\n");
    stream.write_all(out.as_bytes()).expect("head");
    stream.write_all(body).expect("body");
    stream.flush().expect("flush");
}

/// The whole flow, against a registry that behaves the way real ones do:
/// challenge first, then a token, then a manifest, then a blob served from
/// somewhere else entirely.
#[test]
fn a_pull_authenticates_follows_the_blob_redirect_and_verifies_what_arrives() {
    // The storage host, standing in for the CDN a blob download is redirected
    // to. It records whether a credential arrived with the request.
    let storage = TcpListener::bind("127.0.0.1:0").expect("bind storage");
    let storage_port = storage.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let layer = {
        let mut l = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path("etc/hostname").expect("path");
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        l.append(&h, &b"box\n"[..]).expect("append");
        l.into_inner().expect("tar")
    };
    let layer_for_storage = layer.clone();
    let storage_thread = thread::spawn(move || {
        let (mut s, _) = storage.accept().expect("accept storage");
        let req = read_request(&mut s);
        tx.send(req.authorization).expect("send");
        respond(&mut s, "200 OK", &[], &layer_for_storage);
    });

    let sha = |b: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b));
    let config = br#"{"config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#.to_vec();
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{}","size":{}}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{}","size":{}}}]}}"#,
        sha(&config),
        config.len(),
        sha(&layer),
        layer.len()
    )
    .into_bytes();

    let registry = TcpListener::bind("127.0.0.1:0").expect("bind registry");
    let registry_port = registry.local_addr().expect("addr").port();
    let manifest_for_thread = manifest.clone();
    let config_for_thread = config.clone();
    let layer_digest = sha(&layer);
    // The thread cannot know how many requests the client will make, and an
    // `accept` that outlives them would block the join forever. So it runs
    // until the test says stop and is woken by one throwaway connection.
    let done = Arc::new(AtomicBool::new(false));
    let done_for_thread = Arc::clone(&done);
    let registry_thread = thread::spawn(move || {
        let mut challenged = false;
        loop {
            let Ok((mut s, _)) = registry.accept() else {
                return;
            };
            if done_for_thread.load(Ordering::SeqCst) {
                return;
            }
            let req = read_request(&mut s);
            let path = req.line.split(' ').nth(1).unwrap_or_default().to_string();

            if path.starts_with("/token") {
                respond(&mut s, "200 OK", &[], br#"{"token":"the-token"}"#);
                continue;
            }
            // Challenge the first manifest request, the way a registry does.
            if !challenged {
                challenged = true;
                respond(
                    &mut s,
                    "401 Unauthorized",
                    &[(
                        "www-authenticate",
                        &format!(
                            r#"Bearer realm="http://127.0.0.1:{registry_port}/token",service="fake""#
                        ),
                    )],
                    b"",
                );
                continue;
            }
            // Everything after the challenge must carry the token.
            assert_eq!(
                req.authorization.as_deref(),
                Some("Bearer the-token"),
                "the registry's own endpoints must receive the token: {path}"
            );
            if path.contains("/manifests/") {
                respond(
                    &mut s,
                    "200 OK",
                    &[("content-type", "application/vnd.oci.image.manifest.v1+json")],
                    &manifest_for_thread,
                );
            } else if path.contains(&layer_digest) {
                // The layer comes from the storage host — the redirect whose
                // credential handling is the point of this test.
                respond(
                    &mut s,
                    "307 Temporary Redirect",
                    &[("location", &format!("http://127.0.0.1:{storage_port}/blob"))],
                    b"",
                );
            } else {
                respond(&mut s, "200 OK", &[], &config_for_thread);
            }
        }
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("layout");
    let mut puller =
        Puller::new(&format!("localhost:{registry_port}/fake/image:v1")).expect("client");
    let pulled = puller.pull_into(&root).expect("the pull must succeed");

    assert_eq!(pulled.blobs_reused, 0);
    assert!(pulled.bytes_downloaded > 0);
    assert!(root.join("oci-layout").is_file(), "the marker is written");
    assert!(root.join("index.json").is_file(), "and the index, last");

    // The assertion this whole fixture exists for.
    let carried = rx.recv().expect("the storage host was never asked");
    assert_eq!(
        carried, None,
        "the registry's bearer token was forwarded to the storage host"
    );

    done.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(("127.0.0.1", registry_port));
    registry_thread.join().expect("registry thread");
    storage_thread.join().expect("storage thread");

    // What was written is a layout the *reviewed* reader accepts — which is the
    // handover between the two crates, and the only definition of "the pull
    // worked" worth asserting.
    let layout = isopod_oci_unpack::layout::Layout::open(&root).expect("a readable layout");
    let m = layout
        .resolve(&isopod_oci_unpack::layout::Platform::host())
        .expect("resolves");
    assert_eq!(m.layers.len(), 1);
    let blob = layout.blob(&m.layers[0]).expect("verified");

    let dest = dir.path().join("rootfs");
    let mut u = isopod_oci_unpack::Unpacker::create(&dest, isopod_oci_unpack::Limits::default())
        .expect("staging");
    u.apply_layer(blob).expect("unpacks");
    u.finish().expect("promotes");
    assert_eq!(
        std::fs::read_to_string(dest.join("etc/hostname")).expect("read"),
        "box\n"
    );
}

/// A blob already on disk is reused only if it still hashes to its own name.
#[test]
fn a_blob_on_disk_is_reused_only_when_it_is_still_the_blob_it_is_named_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = b"layer bytes";
    let hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
    let d = Digest::parse(&format!("sha256:{hex}")).expect("parse");
    let path = dir.path().join("blob");

    assert!(!blob_is_present(&path, &d, bytes.len() as u64), "absent");
    std::fs::write(&path, bytes).expect("write");
    assert!(blob_is_present(&path, &d, bytes.len() as u64), "present");

    // The neighbours a size check alone would accept: same length, different
    // bytes — a truncated-then-padded download, or a file another build left.
    std::fs::write(&path, b"layer byteZ").expect("write");
    assert!(
        !blob_is_present(&path, &d, bytes.len() as u64),
        "a file of the right size that is not the blob must not be reused"
    );
    // And a size the manifest disagrees with.
    std::fs::write(&path, bytes).expect("write");
    assert!(
        !blob_is_present(&path, &d, 1),
        "the declared size must match"
    );
}

/// The live one, against Docker Hub. Ignored by default: it needs the network
/// and a third party's uptime, neither of which belongs in `cargo test`.
#[test]
#[ignore = "live: pulls alpine from Docker Hub"]
fn a_real_image_pulls_from_docker_hub_and_unpacks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("alpine");
    let mut puller = Puller::new("alpine:3.20").expect("client");
    let pulled = puller.pull_into(&root).expect("the pull must succeed");
    eprintln!(
        "pulled {} ({} bytes, {} reused)",
        pulled.manifest_digest, pulled.bytes_downloaded, pulled.blobs_reused
    );

    let layout = isopod_oci_unpack::layout::Layout::open(&root).expect("layout");
    let m = layout
        .resolve(&isopod_oci_unpack::layout::Platform::host())
        .expect("resolves");
    let cfg = layout.config(&m.config).expect("config");
    eprintln!("env {:?} cmd {:?}", cfg.env, cfg.cmd);

    let dest = dir.path().join("rootfs");
    let mut u = isopod_oci_unpack::Unpacker::create(&dest, isopod_oci_unpack::Limits::default())
        .expect("staging");
    for layer in &m.layers {
        let blob = layout.blob(layer).expect("verified");
        u.apply_layer(flate2::read::GzDecoder::new(blob))
            .expect("unpacks");
    }
    let report = u.finish().expect("promotes");
    eprintln!("{report:?}");
    assert!(
        dest.join("etc/alpine-release").is_file(),
        "a real Alpine root"
    );
    assert!(dest.join("bin/busybox").exists());
}

// --- which credential goes to which registry -----------------------------

/// Write a `config.json` and return its path.
fn config_with(dir: &std::path::Path, json: &str) -> std::path::PathBuf {
    let p = dir.join("config.json");
    std::fs::write(&p, json).expect("write config");
    p
}

#[test]
fn the_hub_credential_is_for_hub_and_for_nothing_else() {
    // The operator has run `docker login` and nothing more. Every registry they
    // subsequently name used to be handed this, on the first request, before
    // any challenge — one command away from posting it to a stranger.
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_with(
        dir.path(),
        r#"{"auths":{"https://index.docker.io/v1/":{"auth":"SECRET-HUB"}}}"#,
    );

    for hub in ["alpine:3.20", "docker.io/library/alpine:3.20", "nginx"] {
        let r = Reference::parse(hub).expect("parses");
        assert_eq!(
            docker_config_auth_in(&cfg, &r).as_deref(),
            Some("SECRET-HUB"),
            "{hub} IS Docker Hub and must still authenticate"
        );
    }
    for elsewhere in [
        "ghcr.io/someone/app:v1",
        "evil.example.com/x/y:latest",
        "quay.io/org/thing:1",
        "localhost:5000/mine:1",
        "index.docker.io.evil.com/x/y",
    ] {
        let r = Reference::parse(elsewhere).expect("parses");
        assert_eq!(
            docker_config_auth_in(&cfg, &r),
            None,
            "{elsewhere} must not receive the operator's Docker Hub credential"
        );
    }
}

#[test]
fn a_credential_is_matched_to_its_own_registry_by_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_with(
        dir.path(),
        r#"{"auths":{
             "ghcr.io":{"auth":"GHCR"},
             "https://quay.io/v1/":{"auth":"QUAY"},
             "http://localhost:5000":{"auth":"LOCAL"}
           }}"#,
    );
    for (reference, want) in [
        ("ghcr.io/o/a:1", Some("GHCR")),
        // A key stored with a scheme and a path still names its host, which is
        // the reduction Docker's own resolution does.
        ("quay.io/o/a:1", Some("QUAY")),
        ("localhost:5000/o/a:1", Some("LOCAL")),
        // Neighbours that must NOT match: a key is a host, not a pattern.
        ("ghcr.io.evil.com/o/a:1", None),
        ("evilghcr.io/o/a:1", None),
        ("sub.ghcr.io/o/a:1", None),
        ("alpine:3.20", None),
    ] {
        let r = Reference::parse(reference).expect("parses");
        assert_eq!(
            docker_config_auth_in(&cfg, &r).as_deref(),
            want,
            "{reference}"
        );
    }
}

#[test]
fn an_empty_auth_is_not_a_credential() {
    // What Docker writes when the secret lives in a credsStore keychain. An
    // empty `Basic ` header is not a degraded credential, it is a broken one.
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_with(
        dir.path(),
        r#"{"auths":{"ghcr.io":{"auth":""},"https://index.docker.io/v1/":{"auth":""}}}"#,
    );
    for reference in ["ghcr.io/o/a:1", "alpine:3.20"] {
        let r = Reference::parse(reference).expect("parses");
        assert_eq!(docker_config_auth_in(&cfg, &r), None, "{reference}");
    }
    // A missing file is not an error either.
    let r = Reference::parse("alpine:3.20").expect("parses");
    assert_eq!(
        docker_config_auth_in(&dir.path().join("nope.json"), &r),
        None
    );
}

/// Two redirects instead of one used to defeat the origin rule entirely.
///
/// `may_carry_credential` compares the two ends of ONE hop. Once the first hop
/// has taken the client to the attacker's origin, the second hop compares their
/// host to their host, says yes, and re-attaches the credential the first hop
/// correctly dropped. The predicate was right and the loop threw its answer
/// away, which is why this test lives here and not in `auth.rs`: nothing about
/// `may_carry_credential` is wrong, and a unit test of it passes either way.
#[test]
fn a_credential_dropped_at_one_hop_does_not_come_back_at_the_next() {
    let storage = TcpListener::bind("127.0.0.1:0").expect("bind storage");
    let storage_port = storage.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel::<Option<String>>();

    let layer = {
        let mut l = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path("etc/hostname").expect("path");
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        l.append(&h, &b"box\n"[..]).expect("append");
        l.into_inner().expect("tar")
    };
    let layer_for_storage = layer.clone();

    // Hop 2 and hop 3 both land here, and both report what they were sent.
    let storage_thread = thread::spawn(move || {
        // Hop 2: cross-origin from the registry. Bounce to ourselves.
        let (mut s, _) = storage.accept().expect("accept 1");
        let req = read_request(&mut s);
        tx.send(req.authorization).expect("send 1");
        respond(
            &mut s,
            "307 Temporary Redirect",
            &[(
                "location",
                &format!("http://127.0.0.1:{storage_port}/blob-for-real"),
            )],
            b"",
        );
        // Hop 3: same origin as hop 2 — where the credential used to return.
        let (mut s, _) = storage.accept().expect("accept 2");
        let req = read_request(&mut s);
        tx.send(req.authorization).expect("send 2");
        respond(&mut s, "200 OK", &[], &layer_for_storage);
    });

    let sha = |b: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b));
    let config = br#"{"config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#.to_vec();
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{}","size":{}}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{}","size":{}}}]}}"#,
        sha(&config),
        config.len(),
        sha(&layer),
        layer.len()
    )
    .into_bytes();

    let registry = TcpListener::bind("127.0.0.1:0").expect("bind registry");
    let registry_port = registry.local_addr().expect("addr").port();
    let layer_digest = sha(&layer);
    let done = Arc::new(AtomicBool::new(false));
    let done_for_thread = Arc::clone(&done);
    let registry_thread = thread::spawn(move || {
        let mut challenged = false;
        loop {
            let Ok((mut s, _)) = registry.accept() else {
                return;
            };
            if done_for_thread.load(Ordering::SeqCst) {
                return;
            }
            let req = read_request(&mut s);
            let path = req.line.split(' ').nth(1).unwrap_or_default().to_string();
            if path.starts_with("/token") {
                respond(&mut s, "200 OK", &[], br#"{"token":"the-token"}"#);
                continue;
            }
            if !challenged {
                challenged = true;
                respond(
                    &mut s,
                    "401 Unauthorized",
                    &[(
                        "www-authenticate",
                        &format!(
                            r#"Bearer realm="http://127.0.0.1:{registry_port}/token",service="fake""#
                        ),
                    )],
                    b"",
                );
                continue;
            }
            if path.contains("/manifests/") {
                respond(
                    &mut s,
                    "200 OK",
                    &[("content-type", "application/vnd.oci.image.manifest.v1+json")],
                    &manifest,
                );
            } else if path.contains(&layer_digest) {
                respond(
                    &mut s,
                    "307 Temporary Redirect",
                    &[("location", &format!("http://127.0.0.1:{storage_port}/blob"))],
                    b"",
                );
            } else {
                respond(&mut s, "200 OK", &[], &config);
            }
        }
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let mut puller =
        Puller::new(&format!("localhost:{registry_port}/fake/image:v1")).expect("client");
    puller
        .pull_into(&dir.path().join("layout"))
        .expect("the pull must succeed");

    assert_eq!(
        rx.recv().expect("storage was never asked"),
        None,
        "hop 2 crossed an origin and must not carry the token"
    );
    assert_eq!(
        rx.recv().expect("storage was asked only once"),
        None,
        "hop 3 stayed inside the attacker's origin, and the credential must \
         NOT have come back — this is the latch"
    );

    done.store(true, Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(("127.0.0.1", registry_port));
    let _ = registry_thread.join();
    let _ = storage_thread.join();
}
