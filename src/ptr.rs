use std::fmt;
use std::net::IpAddr;

/// Error type for PTR address conversion.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PtrParseError(String);

impl fmt::Display for PtrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PtrParseError {}

/// Converts a PTR query name (e.g., "34.216.184.93.in-addr.arpa." or an
/// ip6.arpa name) back to an IP address string for use with reverse lookups.
///
/// This is a direct port of the Go `ptrToAddr` function.
/// Currently used by tests; the main handler uses res_query for PTR lookups
/// which accepts the PTR name directly.
#[allow(dead_code)]
pub fn ptr_to_addr(name: &str) -> Result<String, PtrParseError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let lower = name.to_lowercase();

    if let Some(trimmed) = lower.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 4 {
            return Err(PtrParseError(format!(
                "expected 4 octets, got {}",
                parts.len()
            )));
        }
        let reversed: Vec<&str> = parts.into_iter().rev().collect();
        let addr_str = reversed.join(".");
        if addr_str.parse::<IpAddr>().is_err() {
            return Err(PtrParseError(format!("invalid IPv4 address: {}", addr_str)));
        }
        return Ok(addr_str);
    }

    if let Some(trimmed) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = trimmed.split('.').collect();
        if nibbles.len() != 32 {
            return Err(PtrParseError(format!(
                "expected 32 nibbles, got {}",
                nibbles.len()
            )));
        }
        let reversed: Vec<&str> = nibbles.into_iter().rev().collect();
        let mut groups = Vec::new();
        for chunk in reversed.chunks(4) {
            groups.push(chunk.join(""));
        }
        let addr_str = groups.join(":");
        if addr_str.parse::<IpAddr>().is_err() {
            return Err(PtrParseError(format!("invalid IPv6 address: {}", addr_str)));
        }
        return Ok(addr_str);
    }

    Err(PtrParseError("not a reverse DNS name".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ptr_to_addr_ipv4() {
        let addr = ptr_to_addr("34.216.184.93.in-addr.arpa.").unwrap();
        assert_eq!(addr, "93.184.216.34");
    }

    #[test]
    fn test_ptr_to_addr_ipv6() {
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
        let addr = ptr_to_addr(name).unwrap();
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
                ptr_to_addr(c).is_err(),
                "expected error for {:?}, got Ok",
                c
            );
        }
    }
}
