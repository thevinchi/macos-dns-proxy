use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Record, RecordType};

/// Error type for DNS resolution operations.
#[derive(Debug)]
pub enum ResolveError {
    /// DNS name not found (NXDOMAIN).
    NotFound,
    /// Resolution failed with an error message.
    Failed(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::NotFound => write!(f, "name not found"),
            ResolveError::Failed(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Trait abstracting DNS resolution, allowing the system resolver to be
/// swapped with a mock in tests.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve A/AAAA records via getaddrinfo. Returns IP addresses.
    async fn lookup_host(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError>;

    /// Query specific DNS record types via the system resolver (res_query).
    /// Used for CNAME, MX, TXT, SRV, NS, PTR queries.
    /// Returns the answer records from the DNS response.
    async fn query_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError>;
}

/// Returns true if the query type is handled via the system resolver.
pub fn is_supported_by_system_resolver(qtype: RecordType) -> bool {
    matches!(
        qtype,
        RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::MX
            | RecordType::TXT
            | RecordType::SRV
            | RecordType::NS
            | RecordType::PTR
    )
}

// ---------------------------------------------------------------------------
// SystemResolver -- production implementation using OS resolver functions
// ---------------------------------------------------------------------------

/// Production resolver that uses macOS/Linux system resolver functions.
/// - A/AAAA queries use `getaddrinfo` (via the `dns-lookup` crate).
/// - CNAME/MX/TXT/SRV/NS/PTR queries use `res_query` (via FFI).
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn lookup_host(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let name = name.trim_end_matches('.').to_string();
        tokio::task::spawn_blocking(move || {
            dns_lookup::lookup_host(&name).map_err(|e| {
                let msg = e.to_string().to_lowercase();
                if msg.contains("not found")
                    || msg.contains("no address")
                    || msg.contains("nodename nor servname")
                    || msg.contains("name or service not known")
                {
                    ResolveError::NotFound
                } else {
                    ResolveError::Failed(e.to_string())
                }
            })
        })
        .await
        .map_err(|e| ResolveError::Failed(format!("task join error: {}", e)))?
    }

    async fn query_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError> {
        let name = name.trim_end_matches('.').to_string();
        let rtype = u16::from(record_type);
        tokio::task::spawn_blocking(move || {
            let response_bytes = res_query_ffi(&name, rtype)?;
            let msg = Message::from_vec(&response_bytes)
                .map_err(|e| ResolveError::Failed(format!("DNS parse error: {}", e)))?;

            if msg.response_code() == ResponseCode::NXDomain {
                return Err(ResolveError::NotFound);
            }

            Ok(msg.answers().to_vec())
        })
        .await
        .map_err(|e| ResolveError::Failed(format!("task join error: {}", e)))?
    }
}

// ---------------------------------------------------------------------------
// res_query FFI
// ---------------------------------------------------------------------------

/// Maximum DNS response buffer size.
const RES_QUERY_BUF_SIZE: usize = 4096;

/// DNS class IN (Internet).
const C_IN: i32 = 1;

// Link to libresolv for res_query.
// On macOS this is part of libSystem; on Linux it's a separate library.
#[link(name = "resolv")]
extern "C" {
    fn res_query(
        dname: *const libc::c_char,
        class: libc::c_int,
        rtype: libc::c_int,
        answer: *mut libc::c_uchar,
        anslen: libc::c_int,
    ) -> libc::c_int;
}

/// Call the system's `res_query` function to perform a DNS lookup.
/// Returns the raw DNS wire-format response bytes.
fn res_query_ffi(name: &str, record_type: u16) -> Result<Vec<u8>, ResolveError> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|e| ResolveError::Failed(format!("invalid name: {}", e)))?;
    let mut buf = vec![0u8; RES_QUERY_BUF_SIZE];

    let len = unsafe {
        res_query(
            c_name.as_ptr(),
            C_IN,
            record_type as libc::c_int,
            buf.as_mut_ptr(),
            buf.len() as libc::c_int,
        )
    };

    if len < 0 {
        // res_query returns -1 on error. Common cause: NXDOMAIN.
        // We can't easily distinguish NXDOMAIN from other errors without
        // checking h_errno, so we treat all failures as NotFound.
        // The upstream caller will map this to NXDOMAIN response code.
        return Err(ResolveError::NotFound);
    }

    buf.truncate(len as usize);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported_by_system_resolver() {
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
}
