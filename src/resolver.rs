use std::fmt;
use std::net::IpAddr;

use hickory_proto::rr::{Record, RecordType};

/// Error type for DNS resolution operations.
#[derive(Debug)]
pub enum ResolveError {
    /// DNS name does not exist (maps to NXDOMAIN).
    NotFound,
    /// Resolution failed with an error message (maps to SERVFAIL).
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
pub trait Resolver: Send + Sync {
    /// Resolve A/AAAA records via getaddrinfo. Returns IP addresses.
    fn lookup_host(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send;

    /// Query an arbitrary DNS record type via the system resolver.
    ///
    /// Used for every non-A/AAAA query type (CNAME, MX, TXT, SRV, NS, PTR, SOA,
    /// CAA, and any other type). On macOS this is served by `DNSServiceQueryRecord`
    /// (mDNSResponder), which honors the system's split-DNS configuration.
    ///
    /// Returns the answer records. Semantics of the result:
    /// - `Ok(records)` with records → NOERROR + answers.
    /// - `Ok(vec![])` → the name exists but has no record of this type (NODATA);
    ///   the caller emits NOERROR with an empty answer section.
    /// - `Err(NotFound)` → the name does not exist (NXDOMAIN).
    /// - `Err(Failed(_))` → transient/other failure (SERVFAIL).
    fn query_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> impl std::future::Future<Output = Result<Vec<Record>, ResolveError>> + Send;
}

// ---------------------------------------------------------------------------
// SystemResolver -- production implementation using OS resolver functions
// ---------------------------------------------------------------------------

/// Production resolver that uses the macOS system resolver.
/// - A/AAAA queries use `getaddrinfo` (via the `dns-lookup` crate).
/// - All other query types use `DNSServiceQueryRecord` (mDNSResponder), which,
///   like `getaddrinfo`, honors macOS split-DNS (`scutil --dns`, `/etc/resolver/*`).
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn lookup_host(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let name = name.trim_end_matches('.').to_string();
        tokio::task::spawn_blocking(move || {
            dns_lookup::lookup_host(&name)
                .map(|iter| iter.collect())
                .map_err(|e| {
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
        tokio::task::spawn_blocking(move || query_records_blocking(&name, record_type))
            .await
            .map_err(|e| ResolveError::Failed(format!("task join error: {}", e)))?
    }
}

// ---------------------------------------------------------------------------
// macOS: DNSServiceQueryRecord (mDNSResponder / libSystem)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn query_records_blocking(
    name: &str,
    record_type: RecordType,
) -> Result<Vec<Record>, ResolveError> {
    dns_sd::query(name, record_type)
}

#[cfg(not(target_os = "macos"))]
fn query_records_blocking(
    _name: &str,
    _record_type: RecordType,
) -> Result<Vec<Record>, ResolveError> {
    // DNSServiceQueryRecord is a macOS/mDNSResponder API. Off-macOS the crate
    // still builds and type-checks, but has no system resolver for arbitrary
    // record types, so surface SERVFAIL rather than a false NXDOMAIN.
    Err(ResolveError::Failed(
        "DNSServiceQueryRecord is only available on macOS".to_string(),
    ))
}

/// Raw FFI to mDNSResponder's `DNSServiceQueryRecord` from `dns_sd.h`.
///
/// These symbols live in libSystem on macOS and resolve at link time without any
/// `#[link]` attribute. The API is asynchronous: a query is started, its socket
/// fd is polled, and `DNSServiceProcessResult` drives the reply callback.
#[cfg(target_os = "macos")]
mod dns_sd {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr;
    use std::time::{Duration, Instant};

    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::{BinDecoder, Restrict};

    use super::ResolveError;

    #[allow(non_camel_case_types)]
    type DNSServiceRef = *mut c_void;
    #[allow(non_camel_case_types)]
    type DNSServiceFlags = u32;
    #[allow(non_camel_case_types)]
    type DNSServiceErrorType = i32;

    // Error codes from dns_sd.h (kDNSServiceErr_*). Values verified against
    // Apple's mDNSResponder header (apple-oss-distributions/mDNSResponder,
    // mDNSShared/dns_sd.h): the enum base is kDNSServiceErr_Unknown = -65537.
    const KDNS_SERVICE_ERR_NO_ERROR: DNSServiceErrorType = 0;
    const KDNS_SERVICE_ERR_NO_SUCH_NAME: DNSServiceErrorType = -65538;
    const KDNS_SERVICE_ERR_NO_SUCH_RECORD: DNSServiceErrorType = -65554;
    const KDNS_SERVICE_ERR_TIMEOUT: DNSServiceErrorType = -65568;

    /// `kDNSServiceFlagsMoreComing` — set while further replies for this query are
    /// pending in the same batch; the last reply of a batch has it clear.
    const KDNS_SERVICE_FLAGS_MORE_COMING: DNSServiceFlags = 0x1;

    /// `kDNSServiceFlagsReturnIntermediates` — deliver intermediate results
    /// (e.g. CNAMEs) AND negative answers to the callback promptly, instead of
    /// the query silently waiting (which otherwise makes a nonexistent name hit
    /// our timeout and SERVFAIL instead of returning a prompt NXDOMAIN/NODATA).
    const KDNS_SERVICE_FLAGS_RETURN_INTERMEDIATES: DNSServiceFlags = 0x1000;

    /// DNS class IN (Internet).
    const KDNS_SERVICE_CLASS_IN: u16 = 1;

    /// Bound on how long we wait for replies before giving up (→ SERVFAIL).
    const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

    type DNSServiceQueryRecordReply = unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        error_code: DNSServiceErrorType,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        context: *mut c_void,
    );

    unsafe extern "C" {
        fn DNSServiceQueryRecord(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            callback: DNSServiceQueryRecordReply,
            context: *mut c_void,
        ) -> DNSServiceErrorType;

        fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
        fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;
        fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
    }

    /// State the reply callback writes into, passed across the FFI boundary as a
    /// raw `*mut c_void`. The callback only runs synchronously from inside
    /// `DNSServiceProcessResult`, so there is never concurrent access.
    struct QueryContext {
        /// Owner name to stamp onto every answer record (the queried name).
        qname: Name,
        record_type: RecordType,
        records: Vec<Record>,
        /// First non-success `DNSServiceErrorType` seen, else `NO_ERROR`.
        error: DNSServiceErrorType,
        /// Set once at least one reply has been delivered.
        got_reply: bool,
        /// Mirrors `kDNSServiceFlagsMoreComing` from the latest reply.
        more_coming: bool,
    }

    /// Deallocates the `DNSServiceRef` on scope exit (including error paths).
    struct RefGuard(DNSServiceRef);

    impl Drop for RefGuard {
        fn drop(&mut self) {
            unsafe { DNSServiceRefDeallocate(self.0) };
        }
    }

    /// `extern "C"` reply callback. Must never unwind across the FFI boundary, so
    /// the whole body is wrapped in `catch_unwind`; a panic degrades to SERVFAIL.
    unsafe extern "C" fn query_reply(
        _sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        _interface_index: u32,
        error_code: DNSServiceErrorType,
        _fullname: *const c_char,
        rrtype: u16,
        _rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        context: *mut c_void,
    ) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `context` is the `&mut QueryContext` handed to
            // DNSServiceQueryRecord; the callback runs synchronously under
            // DNSServiceProcessResult, so no aliasing occurs.
            let ctx = unsafe { &mut *(context as *mut QueryContext) };
            ctx.got_reply = true;
            ctx.more_coming = (flags & KDNS_SERVICE_FLAGS_MORE_COMING) != 0;

            if error_code != KDNS_SERVICE_ERR_NO_ERROR {
                if ctx.error == KDNS_SERVICE_ERR_NO_ERROR {
                    ctx.error = error_code;
                }
                return;
            }

            // Only surface answers for the type we asked about; mDNSResponder may
            // deliver intermediate CNAMEs which we do not want to mislabel.
            if RecordType::from(rrtype) != ctx.record_type {
                return;
            }

            let rd: &[u8] = if rdlen == 0 || rdata.is_null() {
                &[]
            } else {
                // SAFETY: mDNSResponder guarantees `rdata` points to `rdlen` valid bytes.
                unsafe { std::slice::from_raw_parts(rdata as *const u8, rdlen as usize) }
            };

            let mut decoder = BinDecoder::new(rd);
            match RData::read(&mut decoder, ctx.record_type, Restrict::new(rdlen)) {
                Ok(parsed) => {
                    ctx.records
                        .push(Record::from_rdata(ctx.qname.clone(), ttl, parsed));
                }
                Err(_) => {
                    // Undecodable rdata is a hard failure, not a "no record".
                    if ctx.error == KDNS_SERVICE_ERR_NO_ERROR {
                        ctx.error = KDNS_SERVICE_ERR_TIMEOUT; // any non-NoSuch* → SERVFAIL
                    }
                }
            }
        }));
    }

    /// Run one `DNSServiceQueryRecord` query to completion (blocking).
    pub fn query(name: &str, record_type: RecordType) -> Result<Vec<Record>, ResolveError> {
        let qname = Name::from_ascii(name)
            .map_err(|e| ResolveError::Failed(format!("invalid name {name:?}: {e}")))?;
        let c_name = CString::new(name)
            .map_err(|e| ResolveError::Failed(format!("invalid name {name:?}: {e}")))?;

        let mut ctx = QueryContext {
            qname,
            record_type,
            records: Vec::new(),
            error: KDNS_SERVICE_ERR_NO_ERROR,
            got_reply: false,
            more_coming: false,
        };

        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        let start_err = unsafe {
            DNSServiceQueryRecord(
                &mut sd_ref,
                KDNS_SERVICE_FLAGS_RETURN_INTERMEDIATES,
                0,
                c_name.as_ptr(),
                u16::from(record_type),
                KDNS_SERVICE_CLASS_IN,
                query_reply,
                (&mut ctx as *mut QueryContext).cast::<c_void>(),
            )
        };
        if start_err != KDNS_SERVICE_ERR_NO_ERROR {
            return Err(ResolveError::Failed(format!(
                "DNSServiceQueryRecord start failed: {start_err}"
            )));
        }
        let _guard = RefGuard(sd_ref);

        let fd = unsafe { DNSServiceRefSockFD(sd_ref) };
        if fd < 0 {
            return Err(ResolveError::Failed(
                "DNSServiceRefSockFD returned an invalid fd".to_string(),
            ));
        }

        let deadline = Instant::now() + QUERY_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || !poll_readable(fd, remaining)? {
                return Err(ResolveError::Failed(
                    "DNSServiceQueryRecord timed out".to_string(),
                ));
            }

            let proc_err = unsafe { DNSServiceProcessResult(sd_ref) };
            if proc_err != KDNS_SERVICE_ERR_NO_ERROR {
                return Err(ResolveError::Failed(format!(
                    "DNSServiceProcessResult failed: {proc_err}"
                )));
            }

            if ctx.error != KDNS_SERVICE_ERR_NO_ERROR {
                return map_error(ctx.error);
            }
            if ctx.got_reply && !ctx.more_coming {
                return Ok(std::mem::take(&mut ctx.records));
            }
        }
    }

    /// Map a terminal `DNSServiceErrorType` to a [`ResolveError`] outcome.
    fn map_error(error: DNSServiceErrorType) -> Result<Vec<Record>, ResolveError> {
        match error {
            // Name exists but has no record of this type → NODATA (NOERROR, empty).
            KDNS_SERVICE_ERR_NO_SUCH_RECORD => Ok(Vec::new()),
            // Name does not exist → NXDOMAIN.
            KDNS_SERVICE_ERR_NO_SUCH_NAME => Err(ResolveError::NotFound),
            // Timeout and everything else → SERVFAIL so clients retry.
            other => Err(ResolveError::Failed(format!("dns-sd error {other}"))),
        }
    }

    /// Block until `fd` is readable or `timeout` elapses. Retries on `EINTR`.
    /// Returns `Ok(true)` if readable, `Ok(false)` on timeout.
    fn poll_readable(fd: c_int, timeout: Duration) -> Result<bool, ResolveError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let ms = remaining.as_millis().min(c_int::MAX as u128) as c_int;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ResolveError::Failed(format!("poll failed: {err}")));
            }
            return Ok(rc > 0 && (pfd.revents & libc::POLLIN) != 0);
        }
    }
}
