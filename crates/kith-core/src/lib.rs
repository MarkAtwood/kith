pub mod auth;
pub mod chat;
pub mod contact;
pub mod error;
pub mod events;
pub mod jmap;
pub mod message;
pub mod resultref;

// Re-export primary types at crate level for ergonomic downstream imports.
pub use auth::{Identity, Role};
pub use chat::Chat;
pub use contact::ChatContact;
pub use error::{AuthError, JmapError, KithError};
pub use events::{parse_sse_frame, SseFrame, StateChange};
pub use jmap::{Id, Invocation, JmapRequest, JmapResponse, UTCDate};
pub use message::{Attachment, DeliveryState, Message};
pub use resultref::{Argument, ResultReference};

/// Returns `true` if `ip` is in the address space reserved for Tailscale peers:
/// - IPv4 `100.64.0.0/10` (CGNAT range used by Tailscale)
/// - IPv6 `fc00::/7` (ULA; Tailscale uses `fd7a:115c:a1e0::/48` within this)
///
/// All other addresses — loopback, unspecified, RFC 1918 private, link-local,
/// and public internet — return `false`.
///
/// Both `kith-peer` and `kithd` use this function for IP-range validation so
/// that any change to the allowed ranges is made in one place only.
pub fn is_tailnet_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Accept only Tailscale CGNAT range 100.64.0.0/10.
            // First octet must be 100; second octet must be 64–127.
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // Reject link-local: fe80::/10 (top 10 bits = 1111 1110 10).
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // Accept only ULA: fc00::/7 (first byte 0xfc or 0xfd).
            (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Maximum body size for a chat message (bytes).
pub const MAX_BODY_BYTES: usize = 65_536;
/// Maximum attachment size (bytes).
pub const MAX_ATTACHMENT_BYTES: usize = 104_857_600;

/// Format a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) as an
/// RFC 3339 UTC string (e.g., `"2020-09-13T12:26:40Z"`).
///
/// Uses the Hinnant civil-calendar algorithm for accuracy without an
/// external time crate.  Correct for dates from the Unix epoch (t=0) through 2299.
///
/// The parameter type is `u64` to enforce at the type level that only
/// non-negative values (i.e. valid Unix epoch seconds) are accepted.
///
/// Single canonical implementation shared by `kith-store` and `kith-peer`.
pub fn unix_secs_to_rfc3339(secs: u64) -> String {
    let secs_in_day: u64 = 86400;
    let days = secs / secs_in_day;
    let time_secs = secs % secs_in_day;

    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    // Civil date from days since epoch (1970-01-01).
    // Source: https://howardhinnant.github.io/date_algorithms.html
    // Widen to i64 for the signed arithmetic required by the algorithm.
    let days = days as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn is_tailnet_ip_accepts_cgnat() {
        // Oracle: Tailscale CGNAT range is 100.64.0.0/10 (RFC 6598).
        assert!(is_tailnet_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("100.100.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("100.127.255.254".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_tailnet_ip_rejects_outside_cgnat() {
        // Oracle: addresses just outside CGNAT range.
        assert!(!is_tailnet_ip("100.63.255.255".parse::<IpAddr>().unwrap())); // one below
        assert!(!is_tailnet_ip("100.128.0.0".parse::<IpAddr>().unwrap())); // one above
        assert!(!is_tailnet_ip("10.0.0.1".parse::<IpAddr>().unwrap())); // RFC 1918
        assert!(!is_tailnet_ip("192.168.1.1".parse::<IpAddr>().unwrap())); // RFC 1918
        assert!(!is_tailnet_ip("172.16.0.1".parse::<IpAddr>().unwrap())); // RFC 1918
        assert!(!is_tailnet_ip("169.254.1.1".parse::<IpAddr>().unwrap())); // link-local
        assert!(!is_tailnet_ip("127.0.0.1".parse::<IpAddr>().unwrap())); // loopback
        assert!(!is_tailnet_ip("8.8.8.8".parse::<IpAddr>().unwrap())); // public
    }

    #[test]
    fn is_tailnet_ip_accepts_ula_ipv6() {
        // Oracle: Tailscale IPv6 range is within fc00::/7 (ULA).
        assert!(is_tailnet_ip(
            "fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_tailnet_ip("fd00::1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("fc00::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_tailnet_ip_rejects_non_ula_ipv6() {
        // Oracle: link-local, loopback, and public IPv6 are rejected.
        assert!(!is_tailnet_ip("fe80::1".parse::<IpAddr>().unwrap())); // link-local
        assert!(!is_tailnet_ip("::1".parse::<IpAddr>().unwrap())); // loopback
        assert!(!is_tailnet_ip("2001:db8::1".parse::<IpAddr>().unwrap())); // documentation (public)
        assert!(!is_tailnet_ip("2600::1".parse::<IpAddr>().unwrap())); // public
        assert!(!is_tailnet_ip("::".parse::<IpAddr>().unwrap())); // unspecified
    }

    #[test]
    fn unix_secs_to_rfc3339_known_values() {
        // Independent oracle: well-known Unix timestamps cross-checked with
        // `date -u -d @N '+%Y-%m-%dT%H:%M:%SZ'` on a POSIX system and Python 3.
        assert_eq!(unix_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_secs_to_rfc3339(86400), "1970-01-02T00:00:00Z");
        // Oracle: Python 3 datetime.fromtimestamp(1_000_000_000, UTC) => '2001-09-09T01:46:40+00:00'
        assert_eq!(unix_secs_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // Oracle: Python 3 datetime.datetime(2026,4,18,12,34,56,tzinfo=UTC).timestamp() => 1776515696
        assert_eq!(unix_secs_to_rfc3339(1776515696), "2026-04-18T12:34:56Z");
        // Oracle: date -d "2000-02-29T00:00:00Z" +%s => 951782400 (leap day)
        assert_eq!(unix_secs_to_rfc3339(951782400), "2000-02-29T00:00:00Z");
        // Oracle: date -d "2023-12-31T23:59:59Z" +%s => 1704067199
        assert_eq!(unix_secs_to_rfc3339(1704067199), "2023-12-31T23:59:59Z");
    }
}
