/// Format a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) as an
/// RFC 3339 UTC string (e.g., `"2020-09-13T12:26:40Z"`).
///
/// Delegates to [`kith_core::unix_secs_to_rfc3339`]; the single canonical
/// implementation lives in `kith-core`.
pub(crate) fn unix_secs_to_rfc3339(secs: u64) -> String {
    kith_core::unix_secs_to_rfc3339(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_secs_to_rfc3339_known_values() {
        // Independent oracle: well-known Unix timestamps cross-checked with
        // `date -u -d @N '+%Y-%m-%dT%H:%M:%SZ'` on a POSIX system and Python 3
        // (UTC-aware datetime).
        // 0 = Unix epoch = 1970-01-01T00:00:00Z
        assert_eq!(unix_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 86400 = exactly one day after epoch
        assert_eq!(unix_secs_to_rfc3339(86400), "1970-01-02T00:00:00Z");
        // 1_000_000_000 = well-known Unix milestone (2001-09-09T01:46:40Z)
        assert_eq!(unix_secs_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // Oracle: 2026-04-18T12:34:56Z = 1776515696 seconds since epoch.
        // Verified with Python 3:
        //   datetime.datetime(2026,4,18,12,34,56,tzinfo=datetime.timezone.utc).timestamp()
        //   => 1776515696
        assert_eq!(unix_secs_to_rfc3339(1776515696), "2026-04-18T12:34:56Z");
        // Oracle: 2000-02-29T00:00:00Z = 951782400 seconds (leap day).
        // Verified with: date -d "2000-02-29T00:00:00Z" +%s => 951782400
        assert_eq!(unix_secs_to_rfc3339(951782400), "2000-02-29T00:00:00Z");
        // Oracle: 2023-12-31T23:59:59Z = 1704067199 seconds.
        // Verified with: date -d "2023-12-31T23:59:59Z" +%s => 1704067199
        assert_eq!(unix_secs_to_rfc3339(1704067199), "2023-12-31T23:59:59Z");
        // Oracle: Python 3 datetime.fromtimestamp(1_745_000_000, UTC)
        // => '2025-04-18T18:13:20Z'
        assert_eq!(unix_secs_to_rfc3339(1_745_000_000), "2025-04-18T18:13:20Z");
        // Oracle: Python 3 datetime.fromtimestamp(1_750_000_000, UTC)
        // => '2025-06-15T15:06:40Z'
        assert_eq!(unix_secs_to_rfc3339(1_750_000_000), "2025-06-15T15:06:40Z");
    }
}
