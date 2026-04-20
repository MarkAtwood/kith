/// Format a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) as an
/// RFC 3339 UTC string (e.g., "2020-09-13T12:26:40Z").
///
/// Uses the Hinnant civil-calendar algorithm for accuracy without an
/// external time crate. Correct for dates from 1970-03-01 through 2299.
pub(crate) fn unix_secs_to_rfc3339(secs: i64) -> String {
    // Manual implementation: avoid pulling in a date-time crate.
    // Compute year/month/day/hour/min/sec from Unix epoch seconds.
    // Algorithm: Euclidean / astronomical calendar arithmetic.
    let secs_in_day: i64 = 86400;
    let days = secs.div_euclid(secs_in_day);
    let time_secs = secs.rem_euclid(secs_in_day);

    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    // Civil date from days since epoch (1970-01-01).
    // Source: https://howardhinnant.github.io/date_algorithms.html
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
