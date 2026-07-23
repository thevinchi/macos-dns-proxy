//! Integration tests for macos-dns-proxy.
//!
//! Tests the full DNS proxy pipeline end-to-end using mock resolvers. All
//! servers bind to ephemeral ports on localhost for full test isolation.
//!
//! Routing under test: A/AAAA go through `lookup_host` (getaddrinfo); every other
//! type goes through `query_records` (DNSServiceQueryRecord on macOS). There is
//! no default upstream path — the mock resolver stands in for the system
//! resolver on all types.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, MX, NS, PTR as PtrRData, SOA, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use rstest::rstest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use macos_dns_proxy::handler;
use macos_dns_proxy::resolver::{ResolveError, Resolver};

// ---------------------------------------------------------------------------
// Deterministic message ID generator
// ---------------------------------------------------------------------------

static NEXT_MSG_ID: AtomicU16 = AtomicU16::new(1);

fn next_msg_id() -> u16 {
    NEXT_MSG_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// MockResolver -- test implementation that returns canned data
// ---------------------------------------------------------------------------

struct MockResolver {
    hosts: HashMap<String, Vec<IpAddr>>,
    records: HashMap<(String, RecordType), Vec<Record>>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            records: HashMap::new(),
        }
    }

    fn add_host(&mut self, name: &str, addrs: Vec<IpAddr>) {
        self.hosts.insert(name.to_string(), addrs);
    }

    fn add_records(&mut self, name: &str, rtype: RecordType, records: Vec<Record>) {
        self.records.insert((name.to_string(), rtype), records);
    }
}

impl Resolver for MockResolver {
    async fn lookup_host(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let name = name.trim_end_matches('.');
        self.hosts.get(name).cloned().ok_or(ResolveError::NotFound)
    }

    async fn query_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError> {
        let name = name.trim_end_matches('.');
        // A present-but-empty entry models NODATA (name exists, no such record):
        // Ok(vec![]). A missing entry models NXDOMAIN: Err(NotFound).
        self.records
            .get(&(name.to_string(), record_type))
            .cloned()
            .ok_or(ResolveError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// FailingMockResolver -- always returns ResolveError::Failed
// ---------------------------------------------------------------------------

struct FailingMockResolver;

impl Resolver for FailingMockResolver {
    async fn lookup_host(&self, _name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Err(ResolveError::Failed("mock resolver failure".to_string()))
    }

    async fn query_records(
        &self,
        _name: &str,
        _record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError> {
        Err(ResolveError::Failed("mock resolver failure".to_string()))
    }
}

/// Build a full mock resolver with canned data for all supported record types.
fn full_mock_resolver() -> MockResolver {
    let mut resolver = MockResolver::new();
    let name = Name::from_ascii("example.com.").unwrap();

    // A record
    resolver.add_host(
        "example.com",
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    );

    // AAAA record -- add both v4 and v6 to the host list
    resolver.add_host(
        "example-v6.com",
        vec![IpAddr::V6(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        )],
    );

    // For filtering tests: a host with both IPv4 and IPv6 addresses.
    resolver.add_host(
        "example-both.com",
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
        ],
    );

    // CNAME record
    resolver.add_records(
        "example.com",
        RecordType::CNAME,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("alias.example.com.").unwrap())),
        )],
    );

    // MX record
    resolver.add_records(
        "example.com",
        RecordType::MX,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
        )],
    );

    // TXT record
    resolver.add_records(
        "example.com",
        RecordType::TXT,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::TXT(TXT::new(vec![
                "v=spf1 include:example.com ~all".to_string(),
            ])),
        )],
    );

    // NS record
    resolver.add_records(
        "example.com",
        RecordType::NS,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::NS(NS(Name::from_ascii("ns1.example.com.").unwrap())),
        )],
    );

    // SRV record
    resolver.add_records(
        "example.com",
        RecordType::SRV,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::SRV(SRV::new(
                10,
                5,
                5060,
                Name::from_ascii("sip.example.com.").unwrap(),
            )),
        )],
    );

    // SOA record -- now served by the system resolver (was upstream-only before).
    resolver.add_records(
        "example.com",
        RecordType::SOA,
        vec![Record::from_rdata(
            name.clone(),
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("admin.example.com.").unwrap(),
                2024010101,
                3600,
                600,
                604800,
                60,
            )),
        )],
    );

    // PTR record (reverse lookup for 93.184.216.34)
    let ptr_name = Name::from_ascii("34.216.184.93.in-addr.arpa.").unwrap();
    resolver.add_records(
        "34.216.184.93.in-addr.arpa",
        RecordType::PTR,
        vec![Record::from_rdata(
            ptr_name,
            60,
            RData::PTR(PtrRData(Name::from_ascii("example.com.").unwrap())),
        )],
    );

    resolver
}

// ---------------------------------------------------------------------------
// Proxy startup helpers
// ---------------------------------------------------------------------------

/// Start a UDP proxy server with the given resolver.
/// Returns the proxy address and a JoinHandle (caller should abort on cleanup).
async fn start_proxy<R: Resolver + 'static>(
    resolver: Arc<R>,
    verbose: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let request = match Message::from_vec(&buf[..len]) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let response = handler::handle_dns(&request, resolver.as_ref(), src, verbose).await;

            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, src).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    (addr, handle)
}

/// Start a TCP proxy server.
/// Returns the proxy address and a JoinHandle (caller should abort on cleanup).
async fn start_tcp_proxy<R: Resolver + 'static>(
    resolver: Arc<R>,
    verbose: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, src) = match listener.accept().await {
                Ok(r) => r,
                Err(_) => break,
            };

            let resolver = resolver.clone();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut msg_buf = vec![0u8; msg_len];
                if stream.read_exact(&mut msg_buf).await.is_err() {
                    return;
                }

                let request = match Message::from_vec(&msg_buf) {
                    Ok(m) => m,
                    Err(_) => return,
                };

                let response = handler::handle_dns(&request, resolver.as_ref(), src, verbose).await;

                if let Ok(bytes) = response.to_vec() {
                    let len_prefix = (bytes.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&len_prefix).await;
                    let _ = stream.write_all(&bytes).await;
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    (addr, handle)
}

// ---------------------------------------------------------------------------
// Query helper
// ---------------------------------------------------------------------------

/// Send a DNS query to a proxy and return the response.
/// Uses a configurable timeout (default 5 seconds).
async fn query_proxy_with_timeout(
    proxy_addr: SocketAddr,
    proto: &str,
    name: &str,
    qtype: RecordType,
    query_timeout: Duration,
) -> Message {
    let mut msg = Message::new();
    msg.set_id(next_msg_id());
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).unwrap());
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    let msg_bytes = msg.to_vec().unwrap();

    match proto {
        "udp" => {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.send_to(&msg_bytes, proxy_addr).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, _) = timeout(query_timeout, socket.recv_from(&mut buf))
                .await
                .expect("query timeout")
                .expect("recv failed");
            Message::from_vec(&buf[..len]).unwrap()
        }
        "tcp" => {
            let mut stream = timeout(query_timeout, TcpStream::connect(proxy_addr))
                .await
                .expect("connect timeout")
                .expect("connect failed");

            let len_prefix = (msg_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len_prefix).await.unwrap();
            stream.write_all(&msg_bytes).await.unwrap();

            let mut len_buf = [0u8; 2];
            timeout(query_timeout, stream.read_exact(&mut len_buf))
                .await
                .expect("read timeout")
                .expect("read failed");
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await.unwrap();
            Message::from_vec(&resp_buf).unwrap()
        }
        _ => panic!("unsupported protocol"),
    }
}

/// Send a DNS query with default 5-second timeout.
async fn query_proxy(
    proxy_addr: SocketAddr,
    proto: &str,
    name: &str,
    qtype: RecordType,
) -> Message {
    query_proxy_with_timeout(proxy_addr, proto, name, qtype, Duration::from_secs(5)).await
}

// ===========================================================================
// System Resolver Tests (A, AAAA, CNAME, MX, TXT, SRV, NS, PTR)
// ===========================================================================

#[tokio::test]
async fn test_system_resolver_a() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected A record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_aaaa() {
    let mut resolver = full_mock_resolver();
    // Override example.com with only an IPv6 address for this test.
    resolver.add_host(
        "example.com",
        vec![IpAddr::V6(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        )],
    );
    let resolver = Arc::new(resolver);
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::AAAA).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::AAAA(aaaa) => {
            let expected: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
            assert_eq!(aaaa.0, expected);
        }
        other => panic!("expected AAAA record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_mx() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::MX).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::MX(mx) => {
            assert_eq!(mx.exchange().to_ascii(), "mail.example.com.");
            assert_eq!(mx.preference(), 10);
        }
        other => panic!("expected MX record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_txt() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::TXT).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::TXT(txt) => {
            let txt_data: Vec<String> = txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            assert!(
                txt_data.contains(&"v=spf1 include:example.com ~all".to_string()),
                "unexpected TXT value: {:?}",
                txt_data
            );
        }
        other => panic!("expected TXT record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_ns() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::NS).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::NS(ns) => {
            assert_eq!(ns.0.to_ascii(), "ns1.example.com.");
        }
        other => panic!("expected NS record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_cname() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::CNAME).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::CNAME(cname) => {
            assert_eq!(cname.0.to_ascii(), "alias.example.com.");
        }
        other => panic!("expected CNAME record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_srv() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SRV).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::SRV(srv) => {
            assert_eq!(srv.priority(), 10);
            assert_eq!(srv.weight(), 5);
            assert_eq!(srv.port(), 5060);
            assert_eq!(srv.target().to_ascii(), "sip.example.com.");
        }
        other => panic!("expected SRV record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_system_resolver_ptr() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "34.216.184.93.in-addr.arpa.",
        RecordType::PTR,
    )
    .await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::PTR(ptr) => {
            assert_eq!(ptr.0.to_ascii(), "example.com.");
        }
        other => panic!("expected PTR record, got {:?}", other),
    }

    handle.abort();
}

// ===========================================================================
// SOA via the system resolver
//
// SOA (and every other non-A/AAAA type) now flows through query_records, the
// same path as MX/TXT/etc. Previously SOA was forwarded to a (dead-by-default)
// upstream; that path is gone.
// ===========================================================================

#[tokio::test]
async fn test_soa_via_system_udp() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SOA).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::SOA(soa) => {
            assert_eq!(soa.mname().to_ascii(), "ns1.example.com.");
        }
        other => panic!("expected SOA record, got {:?}", other),
    }

    handle.abort();
}

#[tokio::test]
async fn test_soa_via_system_tcp() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_tcp_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "tcp", "example.com.", RecordType::SOA).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    match resp.answers()[0].data() {
        RData::SOA(soa) => {
            assert_eq!(soa.mname().to_ascii(), "ns1.example.com.");
        }
        other => panic!("expected SOA record, got {:?}", other),
    }

    handle.abort();
}

/// A resolver failure on the SOA path must map to SERVFAIL (not NXDOMAIN), over
/// both UDP and TCP.
#[rstest]
#[case::udp("udp")]
#[case::tcp("tcp")]
#[tokio::test]
async fn test_soa_resolver_failure_servfail(#[case] proto: &str) {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, handle) = if proto == "tcp" {
        start_tcp_proxy(resolver, false).await
    } else {
        start_proxy(resolver, false).await
    };

    let resp = query_proxy_with_timeout(
        proxy_addr,
        proto,
        "example.com.",
        RecordType::SOA,
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(resp.response_code(), ResponseCode::ServFail);

    handle.abort();
}

// ===========================================================================
// NODATA -- name exists, no record of the requested type
//
// Exercises the error-mapping fix: an empty answer set (Ok(vec![])) must yield
// NOERROR with no answers, NOT a false NXDOMAIN.
// ===========================================================================

#[tokio::test]
async fn test_nodata_returns_noerror_empty() {
    let mut resolver = MockResolver::new();
    // Present-but-empty entry: the name exists but has no MX record.
    resolver.add_records("example.com", RecordType::MX, vec![]);
    let resolver = Arc::new(resolver);
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::MX).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "NODATA must be NOERROR, not NXDOMAIN"
    );
    assert!(
        resp.answers().is_empty(),
        "NODATA must have an empty answer section"
    );

    handle.abort();
}

// ===========================================================================
// Verbose Logging Tests -- verify verbose mode does not panic on various paths
// ===========================================================================

#[rstest]
#[case::success_path("example.com.", RecordType::A)]
#[case::nxdomain_path("nonexistent.example.com.", RecordType::A)]
#[tokio::test]
async fn test_verbose_logging(#[case] domain: &str, #[case] qtype: RecordType) {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, true).await;

    // Just verify the query completes without panic.
    let _resp = query_proxy(proxy_addr, "udp", domain, qtype).await;

    handle.abort();
}

#[tokio::test]
async fn test_verbose_logging_soa() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, true).await;

    // SOA goes through the system resolver -- verify verbose logging doesn't panic.
    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SOA).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);

    handle.abort();
}

#[tokio::test]
async fn test_verbose_logging_resolver_failure() {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, handle) = start_proxy(resolver, true).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;
    assert_eq!(resp.response_code(), ResponseCode::ServFail);

    handle.abort();
}

// ===========================================================================
// Empty Question Test
// ===========================================================================

#[tokio::test]
async fn test_empty_question_returns_refused() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    // Send an empty query (no questions).
    let mut msg = Message::new();
    msg.set_id(next_msg_id());
    let msg_bytes = msg.to_vec().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg_bytes, proxy_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("query timeout")
        .expect("recv failed");
    let resp = Message::from_vec(&buf[..len]).unwrap();

    // The handler explicitly returns Refused for empty questions.
    assert_eq!(
        resp.response_code(),
        ResponseCode::Refused,
        "expected Refused for empty question, got {:?}",
        resp.response_code()
    );

    handle.abort();
}

// ===========================================================================
// Address Filtering Tests
// ===========================================================================

#[tokio::test]
async fn test_a_query_filters_ipv6() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example-both.com.", RecordType::A).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    for answer in resp.answers() {
        match answer.data() {
            RData::A(_) => {}
            other => panic!("A query should not return non-A records, got {:?}", other),
        }
    }
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        _ => unreachable!(),
    }

    handle.abort();
}

#[tokio::test]
async fn test_aaaa_query_filters_ipv4() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example-both.com.", RecordType::AAAA).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty(), "expected at least one answer");
    for answer in resp.answers() {
        match answer.data() {
            RData::AAAA(_) => {}
            other => panic!(
                "AAAA query should not return non-AAAA records, got {:?}",
                other
            ),
        }
    }
    match resp.answers()[0].data() {
        RData::AAAA(aaaa) => {
            let expected: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
            assert_eq!(aaaa.0, expected);
        }
        _ => unreachable!(),
    }

    handle.abort();
}

// ===========================================================================
// NXDOMAIN Tests -- parameterized across record types and code paths
// ===========================================================================

/// NXDOMAIN for host-lookup path (A/AAAA) and record-query path (MX).
/// Each pair exercises a distinct code path in the handler:
/// - A/AAAA -> resolve_host
/// - MX     -> resolve_via_system
#[rstest]
#[case::a(RecordType::A)]
#[case::mx(RecordType::MX)]
#[tokio::test]
async fn test_nxdomain(#[case] qtype: RecordType) {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "nonexistent.example.com.", qtype).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NXDomain,
        "expected NXDOMAIN for nonexistent {:?} query",
        qtype
    );
    assert!(resp.answers().is_empty(), "expected no answers");

    handle.abort();
}

// ===========================================================================
// Resolver Error Tests -- parameterized across code paths
// ===========================================================================

/// When the resolver returns Failed (not NotFound), the handler should
/// return SERVFAIL. Test both the resolve_host path (A) and
/// the resolve_via_system path (MX).
#[rstest]
#[case::host_lookup_path(RecordType::A)]
#[case::record_query_path(RecordType::MX)]
#[tokio::test]
async fn test_resolver_failed_returns_servfail(#[case] qtype: RecordType) {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", qtype).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL when resolver returns Failed for {:?}",
        qtype
    );

    handle.abort();
}

// ===========================================================================
// Direct Upstream Helper Test
//
// forward_upstream is no longer on the default request path, but remains a
// public helper; verify its protocol validation still holds.
// ===========================================================================

#[tokio::test]
async fn test_forward_upstream_unknown_protocol() {
    let mut msg = Message::new();
    msg.set_id(next_msg_id());

    let result = macos_dns_proxy::upstream::forward_upstream(&msg, "127.0.0.1:53", "sctp").await;

    assert!(result.is_err(), "expected error for unknown protocol");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unsupported protocol"),
        "expected 'unsupported protocol' error, got: {}",
        err_msg
    );
}

// ===========================================================================
// Concurrency Test -- verify proxy handles simultaneous queries
// ===========================================================================

#[tokio::test]
async fn test_concurrent_queries() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    // Fire 10 queries concurrently for different record types.
    let queries: Vec<(&str, RecordType)> = vec![
        ("example.com.", RecordType::A),
        ("example.com.", RecordType::MX),
        ("example.com.", RecordType::TXT),
        ("example.com.", RecordType::NS),
        ("example.com.", RecordType::CNAME),
        ("example.com.", RecordType::SRV),
        ("example.com.", RecordType::SOA),
        ("example.com.", RecordType::A),
        ("example-both.com.", RecordType::A),
        ("example-both.com.", RecordType::AAAA),
    ];

    let mut handles = Vec::new();
    for (domain, qtype) in queries {
        let domain = domain.to_string();
        handles.push(tokio::spawn(async move {
            query_proxy(proxy_addr, "udp", &domain, qtype).await
        }));
    }

    for join_handle in handles {
        let resp = join_handle.await.expect("query task panicked");
        assert_eq!(
            resp.response_code(),
            ResponseCode::NoError,
            "concurrent query failed"
        );
        assert!(
            !resp.answers().is_empty(),
            "concurrent query had no answers"
        );
    }

    handle.abort();
}

// ===========================================================================
// Malformed Message Tests
// ===========================================================================

#[tokio::test]
async fn test_truncated_message() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    // Send garbage bytes that can't be parsed as a DNS message.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&[0x00, 0x01, 0x02], proxy_addr)
        .await
        .unwrap();

    // The proxy should silently drop unparseable messages.
    // Verify by sending a valid query afterward and confirming it still works.
    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(!resp.answers().is_empty());

    handle.abort();
}

#[tokio::test]
async fn test_oversized_question_section() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, handle) = start_proxy(resolver, false).await;

    // Build a message with multiple questions -- only the first should be used.
    let mut msg = Message::new();
    msg.set_id(next_msg_id());
    msg.set_recursion_desired(true);

    let mut q1 = Query::new();
    q1.set_name(Name::from_ascii("example.com.").unwrap());
    q1.set_query_type(RecordType::A);
    q1.set_query_class(DNSClass::IN);
    msg.add_query(q1);

    let mut q2 = Query::new();
    q2.set_name(Name::from_ascii("example.com.").unwrap());
    q2.set_query_type(RecordType::MX);
    q2.set_query_class(DNSClass::IN);
    msg.add_query(q2);

    let msg_bytes = msg.to_vec().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg_bytes, proxy_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("query timeout")
        .expect("recv failed");
    let resp = Message::from_vec(&buf[..len]).unwrap();

    // Should process the first question (A record) and return NoError.
    assert_eq!(resp.response_code(), ResponseCode::NoError);

    handle.abort();
}
