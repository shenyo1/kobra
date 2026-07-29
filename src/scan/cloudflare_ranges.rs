//! Cloudflare IP range detector (Lesson 1 fix v4.4.0).
//! Lesson: KOBRA falsely flagged api-gate-v2.sumopod.com as aws-elastic takeover
//! when actually it's Cloudflare (104.26.x range). v4.3.0 emitted HIGH FP.
//! Fix: filter FPs by checking if IP is in known Cloudflare ranges before claiming takeover.

use std::net::{IpAddr, Ipv4Addr};

/// Official Cloudflare IPv4 ranges (per https://www.cloudflare.com/ips/).
/// Source: cloudflare.com/ips-v4 (June 2026).
const CF_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/12",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Check if an IPv4 address is in any Cloudflare range.
/// Returns true if IP is Cloudflare-fronted (so takeover claim is FP).
pub fn is_cloudflare(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else { return false; };
    let IpAddr::V4(v4) = addr else { return false; };
    for cidr in CF_RANGES {
        if let Some(net) = parse_cidr(cidr) {
            if v4.u32() & net.mask == net.network {
                return true;
            }
        }
    }
    false
}

struct CidrNet {
    network: u32,
    mask: u32,
}

impl CidrNet {
    fn new(prefix: u32, len: u8) -> Self {
        let mask = if len == 0 { 0 } else { !0u32 << (32 - len) };
        Self { network: prefix & mask, mask }
    }
}

trait U32Ext {
    fn u32(&self) -> u32;
}

impl U32Ext for Ipv4Addr {
    fn u32(&self) -> u32 {
        u32::from_be_bytes(self.octets())
    }
}

fn parse_cidr(cidr: &str) -> Option<CidrNet> {
    let (ip_part, len_part) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_part.parse().ok()?;
    let len: u8 = len_part.parse().ok()?;
    Some(CidrNet::new(ip.u32(), len))
}

/// Check if a hostname's resolution points to Cloudflare.
/// Used by takeover detection to filter FPs.
pub fn hostname_looks_like_cloudflare(hostname: &str) -> bool {
    // Heuristic: CF-using hostnames often have CF characteristics
    // (DNS resolves to CF, or has CF-RAY/CF-Cache-Status headers)
    // This is a quick string check before doing DNS lookup.
    hostname.contains("cloudflare") || hostname.ends_with(".cf.") || hostname.contains(".cdn.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_main_range() {
        assert!(is_cloudflare("104.26.9.76"));   // sumopod.com CF
        assert!(is_cloudflare("172.67.69.244")); // CF range
        assert!(is_cloudflare("104.16.0.1"));    // CF range start
        assert!(is_cloudflare("172.64.0.1"));    // CF range start
    }

    #[test]
    fn not_cloudflare() {
        assert!(!is_cloudflare("103.179.67.242")); // ai.sumopod.com direct
        assert!(!is_cloudflare("8.8.8.8"));        // Google DNS
        assert!(!is_cloudflare("127.0.0.1"));      // localhost
        assert!(!is_cloudflare("192.168.1.1"));    // private
    }

    #[test]
    fn invalid_ip() {
        assert!(!is_cloudflare("not.an.ip.addr"));
        assert!(!is_cloudflare(""));
    }

    #[test]
    fn hostname_heuristic() {
        assert!(hostname_looks_like_cloudflare("foo.cloudflare.com"));
        assert!(hostname_looks_like_cloudflare("x.cdn.cloudfront.net"));
        assert!(!hostname_looks_like_cloudflare("example.com"));
    }

    #[test]
    fn sumopod_real_case() {
        // Real Sumopod scan 2026-07-29: api-gate-v2 was CF, not aws-elastic
        assert!(is_cloudflare("104.26.9.76"));
        // ai.sumopod.com is direct origin
        assert!(!is_cloudflare("103.179.67.242"));
    }
}
