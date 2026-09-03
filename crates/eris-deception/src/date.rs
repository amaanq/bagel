//! RFC 9110 `IMF-fixdate` formatting for the `Date`/`Last-Modified` headers.
//!
//! A real HTTP server always stamps `Date`, and serves static files with a
//! `Last-Modified` in the same format. Emitting neither is a fingerprint, so
//! the deceiver formats them here without pulling in a datetime crate.

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format a Unix timestamp (seconds) as an `IMF-fixdate`, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
#[must_use]
pub fn imf_fixdate(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // 1970-01-01 was a Thursday (index 4).
    let weekday = ((days + 4).rem_euclid(7)) as usize;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        min,
        sec
    )
}

/// Convert days since the Unix epoch to a `(year, month, day)` civil date.
///
/// Howard Hinnant's `civil_from_days`, valid across the entire range Eris will
/// ever see.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps_format_correctly() {
        // 0 == the epoch itself.
        assert_eq!(imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // The canonical RFC example instant.
        assert_eq!(imf_fixdate(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        // A leap day.
        assert_eq!(imf_fixdate(1_582_934_400), "Sat, 29 Feb 2020 00:00:00 GMT");
    }
}
