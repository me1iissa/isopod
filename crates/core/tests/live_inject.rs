//! Live wire test for the credential-injection endpoint.
//!
//! Ignored by default (needs outbound HTTPS). Run explicitly with:
//! `cargo test -p isopod-core --test live_inject -- --ignored --nocapture`
//!
//! # Why this exists as a live test
//!
//! Everything about the endpoint that can be decided without a socket is unit
//! tested: parsing, origin pinning, the `allow` match, every refusal body. What
//! those cannot reach is the part where a real token meets a real TLS
//! connection, and that is exactly where the two settings carrying the security
//! argument live:
//!
//! - **redirects are not followed** — a `30x` from the pinned host must come
//!   back to the guest as a `30x`, not be chased with the `Authorization`
//!   header still attached. This is a one-line client setting, it is *not* the
//!   library default, and a refactor that rebuilt the client without it would
//!   pass every offline test in the repo.
//! - **the request is built from parts** — the constructed request must carry
//!   the broker's own `Host`, the broker's own `Authorization`, and none of the
//!   headers the guest tried to smuggle.
//!
//! The upstream is an echo service, so the assertions are made against what the
//! far side actually received rather than against what this process believes it
//! sent. Override it with `ISOPOD_ECHO_HOST` if the default is unavailable.

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use isopod_core::net::broker::{Broker, BrokerPorts, BrokerSpec};
use isopod_core::net::credentials::{load_credentials, Caller, CREDENTIALS_FILE};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// An HTTPS service that echoes the request it received as JSON.
fn echo_host() -> String {
    std::env::var("ISOPOD_ECHO_HOST").unwrap_or_else(|_| "postman-echo.com".to_string())
}

/// The token this test injects. Not a real credential anywhere — the point is
/// to observe *where it lands*, and an echo service reflects it either way.
const TEST_TOKEN: &str = "isopod-live-inject-sentinel";

/// Start a broker on loopback with one credential pinned to the echo host.
async fn broker_with(allow: &str) -> Broker {
    std::env::set_var("ISOPOD_LIVE_INJECT_TOK", TEST_TOKEN);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CREDENTIALS_FILE);
    std::fs::write(
        &path,
        format!(
            r#"{{"version":1,"credentials":{{"echo":{{"host":"{host}","scheme":"bearer",
               "source":"env:ISOPOD_LIVE_INJECT_TOK","allow":[{allow}]}}}}}}"#,
            host = echo_host(),
        ),
    )
    .expect("write store");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let credentials = load_credentials(&["echo".to_string()], Caller::Operator, &path)
        .expect("the test credential must resolve");
    // Keep the tempdir alive for the whole run: the store is read at load time,
    // but a dropped dir on a slow filesystem makes failures confusing.
    std::mem::forget(dir);

    Broker::start(
        BrokerSpec {
            gateway: Ipv4Addr::LOCALHOST,
            // The tests connect over loopback, so loopback *is* the peer the
            // listeners must serve. A real run's guest address is derived from
            // its gateway by `BrokerSpec::new`.
            guest: Ipv4Addr::LOCALHOST,
            rules: Vec::new(),
            credentials,
            // The production posture: this test's upstream is a real public
            // host, so it needs neither exception.
            allow_private: false,
            allow_loopback: false,
            ports: BrokerPorts {
                socks: 0,
                http: 0,
                inject: 0,
                dns: 0,
            },
        }
        .clone(),
    )
    .await
    .expect("broker must start")
}

/// Drive one raw request against the endpoint and return the whole response.
async fn call(broker: &Broker, request: &str) -> String {
    let mut c = TcpStream::connect(broker.inject_addr())
        .await
        .expect("connect to the endpoint");
    c.write_all(request.replace('\n', "\r\n").as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(60), c.read_to_end(&mut buf))
        .await
        .expect("the endpoint must answer, never hang")
        .expect("read response");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Split a chunked response into its head and its decoded body.
fn decode(response: &str) -> (String, String) {
    let (head, rest) = response
        .split_once("\r\n\r\n")
        .expect("a response must have a head");
    let mut body = String::new();
    let mut cursor = rest;
    while let Some((size, tail)) = cursor.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        // A zero-length chunk is the terminator; a short tail means the broker
        // cut the body off without one, which is the truncation signal.
        if n == 0 || tail.len() < n {
            break;
        }
        body.push_str(&tail[..n]);
        cursor = tail[n..].strip_prefix("\r\n").unwrap_or("");
    }
    (head.to_string(), body)
}

#[tokio::test]
#[ignore = "requires outbound HTTPS to an echo service"]
async fn the_request_upstream_is_built_from_parts_and_carries_the_token() {
    let broker = broker_with("\"readonly\"").await;

    // Everything below the request line is the guest trying to steer the
    // credential: a forged Host to relocate it, its own Authorization to
    // impersonate a different principal, X-Forwarded-* to lie about origin.
    let response = call(
        &broker,
        "GET /echo/get?isopod=live HTTP/1.1\n\
         Host: evil.example.com\n\
         Authorization: Bearer attacker-supplied-token\n\
         X-Forwarded-Host: evil.example.com\n\
         Cookie: session=abc\n\
         Accept: application/json\n\n",
    )
    .await;

    let (head, body) = decode(&response);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert!(
        !head.to_ascii_lowercase().contains("content-length"),
        "one framing only: {head}"
    );

    // What the far side actually received.
    let seen: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("echo body was not JSON ({e}): {body}"));
    let headers = seen
        .get("headers")
        .expect("the echo service reports the headers it saw");
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };

    // The token reached the pinned host, attached by the broker.
    assert_eq!(
        header("authorization"),
        format!("Bearer {TEST_TOKEN}"),
        "the broker's own Authorization must be the one that arrived: {headers}"
    );
    // The guest's forged Host did not survive; the pinned one did.
    assert_eq!(header("host"), echo_host(), "{headers}");
    assert!(
        !body.contains("evil.example.com"),
        "nothing the guest sent to relocate the request may reach the wire: {body}"
    );
    // The allowlisted header did survive, because a usable endpoint needs it.
    assert_eq!(header("accept"), "application/json", "{headers}");
    // The dropped ones did not.
    assert!(header("cookie").is_empty(), "{headers}");
    assert!(header("x-forwarded-host").is_empty(), "{headers}");
    // The query rode along untouched — the whole reason `PathGlob` strips it
    // rather than matching against it.
    assert!(
        body.contains("live"),
        "the query must reach upstream: {body}"
    );

    // And the call is on the record, attributed to the pinned host.
    let (events, total) = broker.events();
    assert_eq!(total, 1);
    assert!(events[0].allowed);
    assert_eq!(events[0].host.as_str(), echo_host());
    assert!(events[0].bytes_down > 0, "the response volume is recorded");
}

#[tokio::test]
#[ignore = "requires outbound HTTPS to an echo service"]
async fn a_redirect_is_returned_not_followed() {
    // THE finding this test exists for. `reqwest` follows redirects by default,
    // so without `redirect::Policy::none()` the broker would chase a `Location`
    // the pinned host chose — carrying the `Authorization` header to a server
    // the operator never named. A 30x must come back as a 30x.
    let broker = broker_with("\"readonly\"").await;
    let response = call(
        &broker,
        "GET /echo/redirect-to?url=https%3A%2F%2Fexample.com%2F&status_code=302 HTTP/1.1\n\n",
    )
    .await;

    let (head, _) = decode(&response);
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("unparseable status line: {head}"));
    assert!(
        (300..400).contains(&status),
        "the redirect must be relayed, not chased: {head}"
    );
    // The destination is reported to the guest so it can decide, but the broker
    // did not go there — and if it wants to, it must state that as a new
    // request, which is authorised against `allow` all over again.
    assert!(
        head.to_ascii_lowercase().contains("location:"),
        "the guest is told where it was pointed: {head}"
    );
    assert!(
        !head.contains("200 OK"),
        "a followed redirect would have landed on example.com: {head}"
    );
}

#[tokio::test]
#[ignore = "requires outbound HTTPS to an echo service"]
async fn a_write_outside_the_allow_list_never_reaches_the_wire() {
    // `readonly` is GET|HEAD. A POST is refused host-side, before a connection
    // is opened, so the far side never sees it at all.
    let broker = broker_with("\"readonly\"").await;
    let response = call(&broker, "POST /echo/post HTTP/1.1\nContent-Length: 2\n\nhi").await;
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");

    let (events, _) = broker.events();
    assert_eq!(events.len(), 1);
    assert!(!events[0].allowed);
    assert_eq!(events[0].note, Some("inject-not-permitted"));

    // The same call, with the operator having declared that shape, does reach
    // upstream — so the refusal above is the rule doing its job, not the
    // endpoint being unable to POST.
    let broker = broker_with("\"POST /post\"").await;
    let response = call(
        &broker,
        "POST /echo/post HTTP/1.1\nContent-Type: text/plain\nContent-Length: 12\n\nhello isopod",
    )
    .await;
    let (head, body) = decode(&response);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(
        body.contains("hello isopod"),
        "the declared body must reach upstream: {body}"
    );
    let (events, _) = broker.events();
    assert_eq!(events[0].bytes_up, 12, "the request body is recorded");
}

/// Offline: the store path resolves under `$ISOPOD_HOME`, so a test or a CI run
/// never reads the developer's real credentials.
#[test]
fn the_store_path_follows_isopod_home() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("ISOPOD_HOME", tmp.path());
    let path = isopod_core::net::credentials::store_path().expect("store path");
    assert_eq!(path, tmp.path().join(CREDENTIALS_FILE));
    assert!(path.starts_with(Path::new(tmp.path())));
}
