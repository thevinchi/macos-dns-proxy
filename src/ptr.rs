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
    use rstest::rstest;
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

    #[rstest]
    #[case::not_reverse_dns("example.com.")]
    #[case::too_few_octets("1.2.3.in-addr.arpa.")]
    #[case::non_numeric_octets("x.y.z.w.in-addr.arpa.")]
    fn test_ptr_to_addr_invalid(#[case] input: &str) {
        assert!(
            ptr_to_addr(input).is_err(),
            "expected error for {:?}, got Ok",
            input
        );
    }

    #[test]
    fn test_ptr_to_addr_ipv6_wrong_nibble_count() {
        // Too few nibbles (only 16 instead of 32).
        let short = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
        assert!(
            ptr_to_addr(short).is_err(),
            "expected error for truncated IPv6 PTR name"
        );
    }

    #[test]
    fn test_ptr_to_addr_ipv6_invalid_nibbles() {
        // 32 nibbles but contains 'z' which is not a valid hex nibble.
        let bad = "z.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
        assert!(
            ptr_to_addr(bad).is_err(),
            "expected error for invalid hex nibbles in IPv6 PTR name"
        );
    }

    #[test]
    fn test_ptr_to_addr_no_trailing_dot() {
        // IPv4 PTR without trailing dot should still work.
        let addr = ptr_to_addr("34.216.184.93.in-addr.arpa").unwrap();
        assert_eq!(addr, "93.184.216.34");
    }
}
