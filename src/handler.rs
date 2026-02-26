use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::resolver::{ResolveError, Resolver, is_supported_by_system_resolver};
use crate::upstream;

/// Default TTL for records resolved via getaddrinfo (which doesn't expose TTLs).
const DEFAULT_TTL: u32 = 60;

/// Central DNS request handler. Dispatches queries to the system resolver
/// or upstream server based on query type.
///
/// This is the Rust equivalent of the Go `handleDNS` function.
pub async fn handle_dns<R: Resolver>(
    request: &Message,
    resolver: &R,
    upstream_addr: &str,
    protocol: &str,
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
        RecordType::CNAME
        | RecordType::MX
        | RecordType::TXT
        | RecordType::SRV
        | RecordType::NS
        | RecordType::PTR => resolve_via_system(resolver, request, &qname, qtype).await,
        _ => upstream::forward_upstream(request, upstream_addr, protocol)
            .await
            .map_err(|e| ResolveError::Failed(e.to_string())),
    };

    let elapsed = start.elapsed();

    match result {
        Ok(response) => {
            if verbose {
                let method = if is_supported_by_system_resolver(qtype) {
                    "system"
                } else {
                    "upstream"
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

/// Resolve CNAME/MX/TXT/SRV/NS/PTR queries via the system resolver (res_query).
///
/// Unlike the Go version which uses individual Lookup* methods and constructs
/// records manually, we use res_query which returns full DNS records with
/// real TTLs.
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
