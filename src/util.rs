use chrono::{DateTime, Utc};

/// Formats a UTC `DateTime` to meet HTTP standards.
/// ```
/// use chrono::{TimeZone, Utc};
/// use auth1::util::http_date_fmt;
///
/// assert_eq!(http_date_fmt(Utc.timestamp(0, 0)), "Thu, 01 Jan 1970 00:00:00 GMT");
/// ```
pub fn http_date_fmt(date: DateTime<Utc>) -> String {
    date.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
