use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::resolver::{ResolveError, Resolver};

/// Default TTL for records resolved via getaddrinfo (which doesn't expose TTLs).
const DEFAULT_TTL: u32 = 60;

/// Central DNS request handler. Dispatches queries to the system resolver based
/// on query type: A/AAAA via `getaddrinfo`, everything else via
/// `DNSServiceQueryRecord`. Both paths honor the macOS split-DNS configuration.
///
/// This is the Rust equivalent of the Go `handleDNS` function.
pub async fn handle_dns<R: Resolver>(
    request: &Message,
    resolver: &R,
    remote_addr: SocketAddr,
    verbose: bool,
) -> Message {
    if request.queries().is_empty() {
        return make_error_response(request, ResponseCode::Refused);
    }

    let query = &request.queries()[0];
    let qname = query.name().clone();
    let qtype = query.query_type();
    let start = Instant::now();

    let result = match qtype {
        RecordType::A | RecordType::AAAA => resolve_host(resolver, request, &qname, qtype).await,
        _ => resolve_via_system(resolver, request, &qname, qtype).await,
    };

    let elapsed = start.elapsed();

    match result {
        Ok(response) => {
            if verbose {
                let method = match qtype {
                    RecordType::A | RecordType::AAAA => "getaddrinfo",
                    _ => "dns-sd",
                };
                tracing::info!(
                    "query {} {} from {} -> {} [{}] ({:?})",
                    qname,
                    qtype,
                    remote_addr,
                    response.response_code(),
                    method,
                    elapsed,
                );
            }
            response
        }
        Err(e) => {
            if verbose {
                tracing::info!(
                    "query {} {} from {} -> error: {} ({:?})",
                    qname,
                    qtype,
                    remote_addr,
                    e,
                    elapsed,
                );
            }
            make_error_response(request, ResponseCode::ServFail)
        }
    }
}

/// Resolve A/AAAA queries via the system resolver (getaddrinfo).
///
/// Maps to the Go `resolveHost` function.
async fn resolve_host<R: Resolver>(
    resolver: &R,
    request: &Message,
    name: &Name,
    qtype: RecordType,
) -> Result<Message, ResolveError> {
    let name_str = name.to_ascii();
    let addrs = resolver.lookup_host(&name_str).await;

    // Handle NXDOMAIN.
    let addrs = match addrs {
        Ok(addrs) => addrs,
        Err(ResolveError::NotFound) => {
            let mut resp = make_reply(request);
            resp.set_response_code(ResponseCode::NXDomain);
            return Ok(resp);
        }
        Err(e) => return Err(e),
    };

    let mut response = make_reply(request);

    for addr in addrs {
        match (qtype, addr) {
            (RecordType::A, IpAddr::V4(v4)) => {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    DEFAULT_TTL,
                    RData::A(A(v4)),
                ));
            }
            (RecordType::AAAA, IpAddr::V6(v6)) => {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    DEFAULT_TTL,
                    RData::AAAA(AAAA(v6)),
                ));
            }
            _ => {} // Skip IPv6 addrs for A queries and vice versa.
        }
    }

    Ok(response)
}

/// Resolve every non-A/AAAA query type via the system resolver
/// (`DNSServiceQueryRecord` on macOS), which returns full DNS records with real
/// TTLs and honors split-DNS.
///
/// Error mapping is deliberate: a missing name yields NXDOMAIN, while a name that
/// exists but has no record of the requested type yields NODATA (NOERROR with an
/// empty answer section) rather than a false NXDOMAIN.
async fn resolve_via_system<R: Resolver>(
    resolver: &R,
    request: &Message,
    name: &Name,
    qtype: RecordType,
) -> Result<Message, ResolveError> {
    let name_str = name.to_ascii();
    let records = match resolver.query_records(&name_str, qtype).await {
        Ok(records) => records,
        Err(ResolveError::NotFound) => {
            let mut resp = make_reply(request);
            resp.set_response_code(ResponseCode::NXDomain);
            return Ok(resp);
        }
        Err(e) => return Err(e),
    };

    let mut response = make_reply(request);
    for record in records {
        response.add_answer(record);
    }

    Ok(response)
}

/// Build a DNS response message echoing the request's ID, opcode, and
/// question section. Sets RecursionAvailable = true.
///
/// Equivalent to Go's `dns.Msg.SetReply(r)`.
fn make_reply(request: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NoError);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    response
}

/// Build an error response with the given response code.
fn make_error_response(request: &Message, rcode: ResponseCode) -> Message {
    let mut response = make_reply(request);
    response.set_response_code(rcode);
    response
}
