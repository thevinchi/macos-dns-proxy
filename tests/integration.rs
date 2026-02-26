//! Integration tests for macos-dns-proxy.
//!
//! Ports the Go test suite (main_test.go) to Rust. Uses a MockResolver
//! instead of Go's net.Resolver injection, and mock DNS servers for upstream
//! fallback tests.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR as PtrRData, SOA, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use macos_dns_proxy::handler;
use macos_dns_proxy::resolver::{ResolveError, Resolver};

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
        self.hosts
            .get(name)
            .cloned()
            .ok_or(ResolveError::NotFound)
    }

    async fn query_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError> {
        let name = name.trim_end_matches('.');
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

    // For AAAA test, add v6 address under example.com too
    // (lookup_host returns all addresses; handler filters by type)
    resolver.hosts.insert(
        "example-both.com".to_string(),
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
// Mock upstream DNS server helpers
// ---------------------------------------------------------------------------

/// Start a mock UDP upstream DNS server that returns a canned A record for any query.
async fn start_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();

    let handle = tokio::spawn({
        let socket = socket.clone();
        async move {
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

                let mut response = Message::new();
                response.set_id(request.id());
                response.set_message_type(MessageType::Response);
                response.set_op_code(request.op_code());
                response.set_recursion_desired(request.recursion_desired());
                response.set_recursion_available(true);
                response.set_authoritative(true);
                for q in request.queries() {
                    response.add_query(q.clone());
                }

                if let Some(q) = request.queries().first() {
                    let name = q.name().clone();
                    match q.query_type() {
                        RecordType::A => {
                            response.add_answer(Record::from_rdata(
                                name,
                                60,
                                RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                            ));
                        }
                        RecordType::SOA => {
                            response.add_answer(Record::from_rdata(
                                name,
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
                            ));
                        }
                        _ => {
                            response.set_response_code(ResponseCode::NXDomain);
                        }
                    }
                }

                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, src).await;
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    (addr, handle)
}

/// Start a mock TCP upstream DNS server.
async fn start_mock_tcp_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(r) => r,
                Err(_) => break,
            };

            tokio::spawn(async move {
                // Read length prefix + message.
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

                let mut response = Message::new();
                response.set_id(request.id());
                response.set_message_type(MessageType::Response);
                response.set_op_code(request.op_code());
                response.set_recursion_desired(request.recursion_desired());
                response.set_recursion_available(true);
                response.set_authoritative(true);
                for q in request.queries() {
                    response.add_query(q.clone());
                }

                if let Some(q) = request.queries().first() {
                    response.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }

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
// Proxy startup helpers
// ---------------------------------------------------------------------------

/// Start a UDP proxy server with the given resolver and upstream.
async fn start_proxy(
    resolver: Arc<MockResolver>,
    upstream_addr: &str,
    verbose: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let upstream = upstream_addr.to_string();

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

            let response = handler::handle_dns(
                &request,
                resolver.as_ref(),
                &upstream,
                "udp",
                src,
                verbose,
            )
            .await;

            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, src).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    (addr, handle)
}

/// Start a TCP proxy server.
async fn start_tcp_proxy(
    resolver: Arc<MockResolver>,
    upstream_addr: &str,
    verbose: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = upstream_addr.to_string();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, src) = match listener.accept().await {
                Ok(r) => r,
                Err(_) => break,
            };

            let resolver = resolver.clone();
            let upstream = upstream.clone();
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

                let response = handler::handle_dns(
                    &request,
                    resolver.as_ref(),
                    &upstream,
                    "tcp",
                    src,
                    verbose,
                )
                .await;

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
    msg.set_id(rand::random());
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

// ---------------------------------------------------------------------------
// System Resolver Tests (A, AAAA, CNAME, MX, TXT, SRV, NS)
// ---------------------------------------------------------------------------

/// Port of Go TestSystemResolverA
#[tokio::test]
async fn test_system_resolver_a() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected A record, got {:?}", other),
    }
}

/// Port of Go TestSystemResolverAAAA
#[tokio::test]
async fn test_system_resolver_aaaa() {
    let mut resolver = full_mock_resolver();
    // Add a host with only IPv6 address for this test.
    resolver.hosts.insert(
        "example.com".to_string(),
        vec![IpAddr::V6(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        )],
    );
    let resolver = Arc::new(resolver);
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::AAAA).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::AAAA(aaaa) => {
            let expected: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
            assert_eq!(aaaa.0, expected);
        }
        other => panic!("expected AAAA record, got {:?}", other),
    }
}

/// Port of Go TestSystemResolverMX
#[tokio::test]
async fn test_system_resolver_mx() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::MX).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::MX(mx) => {
            assert_eq!(
                mx.exchange().to_ascii(),
                "mail.example.com.",
                "unexpected MX exchange"
            );
            assert_eq!(mx.preference(), 10, "unexpected MX preference");
        }
        other => panic!("expected MX record, got {:?}", other),
    }
}

/// Port of Go TestSystemResolverTXT
#[tokio::test]
async fn test_system_resolver_txt() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::TXT).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
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
}

/// Port of Go TestSystemResolverNS
#[tokio::test]
async fn test_system_resolver_ns() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::NS).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::NS(ns) => {
            assert_eq!(ns.0.to_ascii(), "ns1.example.com.", "unexpected NS value");
        }
        other => panic!("expected NS record, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Upstream Fallback Tests
// ---------------------------------------------------------------------------

/// Port of Go TestUpstreamFallbackSOA
#[tokio::test]
async fn test_upstream_fallback_soa() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;

    // Use a resolver that would fail -- doesn't matter for SOA since it goes upstream.
    let resolver = Arc::new(MockResolver::new());
    let (proxy_addr, _proxy_handle) =
        start_proxy(resolver, &upstream_addr.to_string(), false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SOA).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::SOA(soa) => {
            assert_eq!(
                soa.mname().to_ascii(),
                "ns1.example.com.",
                "unexpected SOA mname"
            );
        }
        other => panic!("expected SOA record, got {:?}", other),
    }
}

/// Port of Go TestUpstreamFallbackTCP
#[tokio::test]
async fn test_upstream_fallback_tcp() {
    let (upstream_addr, _upstream_handle) = start_mock_tcp_upstream().await;

    let resolver = Arc::new(MockResolver::new());
    let (proxy_addr, _proxy_handle) =
        start_tcp_proxy(resolver, &upstream_addr.to_string(), false).await;

    // SOA query via TCP should go through the upstream fallback.
    let resp = query_proxy(proxy_addr, "tcp", "example.com.", RecordType::SOA).await;

    // The mock TCP upstream returns A records for any query, but won't fail.
    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
}

/// Port of Go TestUnreachableUpstream
#[tokio::test]
async fn test_unreachable_upstream() {
    // Use an address where nothing is listening.
    let dead_upstream = "127.0.0.1:59999";
    let resolver = Arc::new(MockResolver::new());
    let (proxy_addr, _proxy_handle) = start_proxy(resolver, dead_upstream, true).await;

    // SOA goes through upstream fallback, which should fail -> SERVFAIL.
    // Use a longer timeout since the upstream forwarding itself has a 5-second timeout.
    let resp = query_proxy_with_timeout(
        proxy_addr,
        "udp",
        "example.com.",
        RecordType::SOA,
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL"
    );
}

// ---------------------------------------------------------------------------
// Verbose Logging Tests
// ---------------------------------------------------------------------------

/// Port of Go TestVerboseLogging
#[tokio::test]
async fn test_verbose_logging() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", true).await;

    // Query with verbose=true, just verify it doesn't panic.
    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;
    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
}

/// Port of Go TestVerboseLoggingUpstreamFallback
#[tokio::test]
async fn test_verbose_logging_upstream_fallback() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _proxy_handle) =
        start_proxy(resolver, &upstream_addr.to_string(), true).await;

    // SOA goes through upstream -- verify verbose logging doesn't panic.
    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SOA).await;
    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
}

// ---------------------------------------------------------------------------
// PTR Tests (ported from unit tests in main_test.go)
// ---------------------------------------------------------------------------

#[test]
fn test_ptr_to_addr_ipv4() {
    let addr = macos_dns_proxy::ptr::ptr_to_addr("34.216.184.93.in-addr.arpa.").unwrap();
    assert_eq!(addr, "93.184.216.34");
}

#[test]
fn test_ptr_to_addr_ipv6() {
    let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
    let addr = macos_dns_proxy::ptr::ptr_to_addr(name).unwrap();
    let ip: IpAddr = addr.parse().expect("should parse as IP");
    let expected: IpAddr = "2001:0db8::1".parse().unwrap();
    assert_eq!(ip, expected);
}

#[test]
fn test_ptr_to_addr_invalid() {
    let cases = vec![
        "example.com.",
        "1.2.3.in-addr.arpa.",
        "x.y.z.w.in-addr.arpa.",
    ];
    for c in cases {
        assert!(
            macos_dns_proxy::ptr::ptr_to_addr(c).is_err(),
            "expected error for {:?}",
            c
        );
    }
}

// ---------------------------------------------------------------------------
// isSupportedBySystemResolver test
// ---------------------------------------------------------------------------

#[test]
fn test_is_supported_by_system_resolver() {
    use macos_dns_proxy::resolver::is_supported_by_system_resolver;

    let supported = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::TXT,
        RecordType::SRV,
        RecordType::NS,
        RecordType::PTR,
    ];
    for qt in &supported {
        assert!(
            is_supported_by_system_resolver(*qt),
            "expected {:?} to be supported",
            qt
        );
    }

    let unsupported = vec![RecordType::SOA, RecordType::CAA, RecordType::NAPTR];
    for qt in &unsupported {
        assert!(
            !is_supported_by_system_resolver(*qt),
            "expected {:?} to not be supported",
            qt
        );
    }
}

// ---------------------------------------------------------------------------
// Empty Question Test
// ---------------------------------------------------------------------------

/// Port of Go TestEmptyQuestion
#[tokio::test]
async fn test_empty_question() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    // Send an empty query (no questions).
    let mut msg = Message::new();
    msg.set_id(rand::random());
    let msg_bytes = msg.to_vec().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg_bytes, proxy_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("query timeout")
        .expect("recv failed");
    let resp = Message::from_vec(&buf[..len]).unwrap();

    // dns.HandleFailed equivalent returns REFUSED for empty questions.
    assert!(
        resp.response_code() == ResponseCode::Refused
            || resp.response_code() == ResponseCode::ServFail
            || resp.response_code() == ResponseCode::FormErr,
        "expected error rcode for empty question, got {:?}",
        resp.response_code()
    );
}

// ---------------------------------------------------------------------------
// CNAME / SRV / PTR Tests (via handler)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_system_resolver_cname() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::CNAME).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::CNAME(cname) => {
            assert_eq!(
                cname.0.to_ascii(),
                "alias.example.com.",
                "unexpected CNAME target"
            );
        }
        other => panic!("expected CNAME record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_system_resolver_srv() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::SRV).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::SRV(srv) => {
            assert_eq!(srv.priority(), 10, "unexpected SRV priority");
            assert_eq!(srv.weight(), 5, "unexpected SRV weight");
            assert_eq!(srv.port(), 5060, "unexpected SRV port");
            assert_eq!(
                srv.target().to_ascii(),
                "sip.example.com.",
                "unexpected SRV target"
            );
        }
        other => panic!("expected SRV record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_system_resolver_ptr() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "34.216.184.93.in-addr.arpa.",
        RecordType::PTR,
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    let rdata = resp.answers()[0].data();
    match rdata {
        RData::PTR(ptr) => {
            assert_eq!(
                ptr.0.to_ascii(),
                "example.com.",
                "unexpected PTR target"
            );
        }
        other => panic!("expected PTR record, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Address Filtering Tests
// ---------------------------------------------------------------------------

/// A query for a host with both IPv4 and IPv6 should only return IPv4 answers.
#[tokio::test]
async fn test_a_query_filters_ipv6() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example-both.com.", RecordType::A).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    for answer in resp.answers() {
        match answer.data() {
            RData::A(_) => {} // expected
            other => panic!("A query should not return non-A records, got {:?}", other),
        }
    }
    // Verify the IPv4 address is correct.
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        _ => unreachable!(),
    }
}

/// AAAA query for a host with both IPv4 and IPv6 should only return IPv6 answers.
#[tokio::test]
async fn test_aaaa_query_filters_ipv4() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example-both.com.", RecordType::AAAA).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "expected NOERROR"
    );
    assert!(!resp.answers().is_empty(), "expected at least one answer");

    for answer in resp.answers() {
        match answer.data() {
            RData::AAAA(_) => {} // expected
            other => panic!(
                "AAAA query should not return non-AAAA records, got {:?}",
                other
            ),
        }
    }
    // Verify the IPv6 address is correct.
    match resp.answers()[0].data() {
        RData::AAAA(aaaa) => {
            let expected: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
            assert_eq!(aaaa.0, expected);
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// NXDOMAIN Tests
// ---------------------------------------------------------------------------

/// A query for a nonexistent domain should return NXDOMAIN.
#[tokio::test]
async fn test_nxdomain_a() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "nonexistent.example.com.",
        RecordType::A,
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NXDomain,
        "expected NXDOMAIN for nonexistent A query"
    );
    assert!(resp.answers().is_empty(), "expected no answers");
}

/// AAAA query for a nonexistent domain should return NXDOMAIN.
#[tokio::test]
async fn test_nxdomain_aaaa() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "nonexistent.example.com.",
        RecordType::AAAA,
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NXDomain,
        "expected NXDOMAIN for nonexistent AAAA query"
    );
    assert!(resp.answers().is_empty(), "expected no answers");
}

/// MX query for a nonexistent domain should return NXDOMAIN.
#[tokio::test]
async fn test_nxdomain_mx() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "nonexistent.example.com.",
        RecordType::MX,
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NXDomain,
        "expected NXDOMAIN for nonexistent MX query"
    );
    assert!(resp.answers().is_empty(), "expected no answers");
}

/// TXT query for a nonexistent domain should return NXDOMAIN.
#[tokio::test]
async fn test_nxdomain_txt() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "nonexistent.example.com.",
        RecordType::TXT,
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::NXDomain,
        "expected NXDOMAIN for nonexistent TXT query"
    );
    assert!(resp.answers().is_empty(), "expected no answers");
}

// ---------------------------------------------------------------------------
// Resolver Error Tests
// ---------------------------------------------------------------------------

/// When the resolver returns Failed (not NotFound), the handler should
/// return SERVFAIL.
#[tokio::test]
async fn test_resolver_failed_returns_servfail_a() {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL when resolver returns Failed"
    );
}

/// When the resolver returns Failed for a record type query (MX, TXT, etc.),
/// the handler should return SERVFAIL.
#[tokio::test]
async fn test_resolver_failed_returns_servfail_mx() {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", false).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::MX).await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL when resolver returns Failed for MX"
    );
}

// ---------------------------------------------------------------------------
// TCP Upstream Fallback Tests
// ---------------------------------------------------------------------------

/// TCP variant of unreachable upstream -- SOA query via TCP to a dead
/// upstream should return SERVFAIL.
#[tokio::test]
async fn test_unreachable_upstream_tcp() {
    let dead_upstream = "127.0.0.1:59999";
    let resolver = Arc::new(MockResolver::new());
    let (proxy_addr, _proxy_handle) = start_tcp_proxy(resolver, dead_upstream, false).await;

    let resp = query_proxy_with_timeout(
        proxy_addr,
        "tcp",
        "example.com.",
        RecordType::SOA,
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(
        resp.response_code(),
        ResponseCode::ServFail,
        "expected SERVFAIL for unreachable TCP upstream"
    );
}

// ---------------------------------------------------------------------------
// Direct Upstream Tests
// ---------------------------------------------------------------------------

/// forward_upstream with an unknown protocol should return an error.
#[tokio::test]
async fn test_forward_upstream_unknown_protocol() {
    let mut msg = Message::new();
    msg.set_id(rand::random());

    let result =
        macos_dns_proxy::upstream::forward_upstream(&msg, "127.0.0.1:53", "sctp").await;

    assert!(result.is_err(), "expected error for unknown protocol");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unsupported protocol"),
        "expected 'unsupported protocol' error, got: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// Additional PTR Parsing Edge Cases
// ---------------------------------------------------------------------------

#[test]
fn test_ptr_to_addr_ipv6_wrong_nibble_count() {
    // Too few nibbles (only 16 instead of 32).
    let short = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
    assert!(
        macos_dns_proxy::ptr::ptr_to_addr(short).is_err(),
        "expected error for truncated IPv6 PTR name"
    );
}

#[test]
fn test_ptr_to_addr_ipv6_invalid_nibbles() {
    // 32 nibbles but contains 'z' which is not a valid hex nibble.
    let bad = "z.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
    assert!(
        macos_dns_proxy::ptr::ptr_to_addr(bad).is_err(),
        "expected error for invalid hex nibbles in IPv6 PTR name"
    );
}

#[test]
fn test_ptr_to_addr_no_trailing_dot() {
    // IPv4 PTR without trailing dot should still work.
    let addr = macos_dns_proxy::ptr::ptr_to_addr("34.216.184.93.in-addr.arpa").unwrap();
    assert_eq!(addr, "93.184.216.34");
}

// ---------------------------------------------------------------------------
// Verbose Logging Coverage (additional paths)
// ---------------------------------------------------------------------------

/// Verbose logging for NXDOMAIN response (error branch in verbose output).
#[tokio::test]
async fn test_verbose_logging_nxdomain() {
    let resolver = Arc::new(full_mock_resolver());
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", true).await;

    let resp = query_proxy(
        proxy_addr,
        "udp",
        "nonexistent.example.com.",
        RecordType::A,
    )
    .await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
}

/// Verbose logging for a resolver failure (error branch in verbose output).
#[tokio::test]
async fn test_verbose_logging_resolver_failure() {
    let resolver = Arc::new(FailingMockResolver);
    let (proxy_addr, _handle) = start_proxy(resolver, "127.0.0.1:59999", true).await;

    let resp = query_proxy(proxy_addr, "udp", "example.com.", RecordType::A).await;
    assert_eq!(resp.response_code(), ResponseCode::ServFail);
}
