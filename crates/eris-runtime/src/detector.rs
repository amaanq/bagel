//! Bounded, linear-time log record detectors.

use eris_config::Detector;
use eris_core::{Error, Result};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Detection {
    pub network: IpNetwork,
    pub observed_at: u64,
    pub attempt_key: Option<String>,
}

pub(crate) enum CompiledDetector {
    Regex {
        prefilter: Option<Regex>,
        patterns: Vec<Regex>,
        context_patterns: Vec<Regex>,
        max_context_lines: usize,
        context_window_secs: u64,
        context: Mutex<BTreeMap<String, ContextEntry>>,
        ignore: RegexSet,
        address_capture: String,
        timestamp_capture: Option<String>,
        timestamp_format: TimestampFormat,
    },
    Json {
        equals: BTreeMap<String, String>,
        address_pointer: String,
        timestamp_pointer: Option<String>,
        timestamp_format: TimestampFormat,
    },
}

pub(crate) struct ContextEntry {
    last_seen: u64,
    lines: VecDeque<String>,
}

#[derive(Clone)]
pub(crate) enum TimestampFormat {
    Rfc3339,
    Unix,
    Strptime(String),
}

impl CompiledDetector {
    pub fn new(detector: &Detector) -> Result<Self> {
        match detector {
            Detector::Regex {
                prefilter,
                patterns,
                context_patterns,
                max_context_lines,
                context_window_secs,
                ignore_patterns,
                address_capture,
                timestamp_capture,
                timestamp_format,
            } => Ok(Self::Regex {
                prefilter: prefilter
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|error| Error::Pattern(error.to_string()))?,
                patterns: patterns
                    .iter()
                    .map(|pattern| Regex::new(pattern))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|error| Error::Pattern(error.to_string()))?,
                context_patterns: context_patterns
                    .iter()
                    .map(|pattern| Regex::new(pattern))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|error| Error::Pattern(error.to_string()))?,
                max_context_lines: *max_context_lines,
                context_window_secs: *context_window_secs,
                context: Mutex::new(BTreeMap::new()),
                ignore: RegexSet::new(ignore_patterns)
                    .map_err(|error| Error::Pattern(error.to_string()))?,
                address_capture: address_capture.clone(),
                timestamp_capture: timestamp_capture.clone(),
                timestamp_format: parse_timestamp_format(timestamp_format.as_deref())?,
            }),
            Detector::Json {
                equals,
                address_pointer,
                timestamp_pointer,
                timestamp_format,
            } => Ok(Self::Json {
                equals: equals.clone(),
                address_pointer: address_pointer.clone(),
                timestamp_pointer: timestamp_pointer.clone(),
                timestamp_format: parse_timestamp_format(timestamp_format.as_deref())?,
            }),
        }
    }

    /// Match one complete source record. Non-matching and malformed records are
    /// ordinary input, not source failures.
    #[must_use]
    pub fn detect(
        &self,
        record: &str,
        received_at: u64,
        correlation: Option<&str>,
    ) -> Option<Detection> {
        match self {
            Self::Regex {
                prefilter,
                patterns,
                context_patterns,
                max_context_lines,
                context_window_secs,
                context,
                ignore,
                address_capture,
                timestamp_capture,
                timestamp_format,
            } => {
                if ignore.is_match(record) {
                    return None;
                }
                let content = match prefilter {
                    Some(regex) => regex
                        .captures(record)
                        .and_then(|captures| captures.name("content"))?
                        .as_str(),
                    None => record,
                };
                let detect = |text: &str, patterns: &[Regex]| {
                    patterns.iter().find_map(|pattern| {
                        let captures = pattern.captures(text)?;
                        let network = parse_network(captures.name(address_capture)?.as_str())?;
                        let observed_at = timestamp_capture
                            .as_deref()
                            .and_then(|name| captures.name(name))
                            .and_then(|value| parse_timestamp(value.as_str(), timestamp_format))
                            .unwrap_or(received_at);
                        Some(Detection {
                            network,
                            observed_at,
                            attempt_key: captures
                                .name("attempt_key")
                                .map(|value| value.as_str().to_owned()),
                        })
                    })
                };
                let direct = detect(content, patterns);
                if context_patterns.is_empty() {
                    return direct;
                }
                let Some(key) = correlation else {
                    return direct;
                };
                let mut cache = context.lock();
                let stale_before = received_at.saturating_sub(*context_window_secs);
                cache.retain(|_, entry| entry.last_seen >= stale_before);
                if !cache.contains_key(key)
                    && cache.len() >= 4096
                    && let Some(oldest) = cache
                        .iter()
                        .min_by_key(|(_, entry)| entry.last_seen)
                        .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                }
                let entry = cache.entry(key.to_owned()).or_insert_with(|| ContextEntry {
                    last_seen: received_at,
                    lines: VecDeque::new(),
                });
                let mut joined = entry.lines.iter().fold(String::new(), |mut joined, line| {
                    if !joined.is_empty() {
                        joined.push('\n');
                    }
                    joined.push_str(line);
                    joined
                });
                if !joined.is_empty() {
                    joined.push('\n');
                }
                joined.push_str(content);
                let contextual = detect(&joined, context_patterns);
                entry.last_seen = received_at;
                entry.lines.push_back(content.to_owned());
                while entry.lines.len() > *max_context_lines {
                    entry.lines.pop_front();
                }
                direct.or(contextual)
            }
            Self::Json {
                equals,
                address_pointer,
                timestamp_pointer,
                timestamp_format,
            } => {
                let value: Value = serde_json::from_str(record).ok()?;
                if !equals.iter().all(|(pointer, expected)| {
                    value
                        .pointer(pointer)
                        .is_some_and(|actual| json_value_matches(actual, expected))
                }) {
                    return None;
                }
                let network = parse_network(value.pointer(address_pointer)?.as_str()?)?;
                let observed_at = timestamp_pointer
                    .as_deref()
                    .and_then(|pointer| value.pointer(pointer))
                    .and_then(Value::as_str)
                    .and_then(|raw| parse_timestamp(raw, timestamp_format))
                    .unwrap_or(received_at);
                Some(Detection {
                    network,
                    observed_at,
                    attempt_key: None,
                })
            }
        }
    }
}

fn json_value_matches(actual: &Value, expected: &str) -> bool {
    match actual {
        Value::Null => expected == "null",
        Value::Bool(value) => expected.parse::<bool>() == Ok(*value),
        Value::Number(value) => {
            value
                .as_i64()
                .is_some_and(|value| expected.parse::<i64>() == Ok(value))
                || value
                    .as_u64()
                    .is_some_and(|value| expected.parse::<u64>() == Ok(value))
                || value
                    .as_f64()
                    .is_some_and(|value| expected.parse::<f64>() == Ok(value))
        }
        Value::String(value) => value == expected,
        Value::Array(_) | Value::Object(_) => false,
    }
}

fn parse_network(raw: &str) -> Option<IpNetwork> {
    if raw.contains('/') {
        raw.parse().ok()
    } else {
        let address = raw.parse::<IpAddr>().ok()?;
        IpNetwork::new(address, if address.is_ipv4() { 32 } else { 128 }).ok()
    }
}

fn parse_timestamp_format(format: Option<&str>) -> Result<TimestampFormat> {
    match format.unwrap_or("rfc3339") {
        "rfc3339" => Ok(TimestampFormat::Rfc3339),
        "unix" => Ok(TimestampFormat::Unix),
        format if format.starts_with("strptime:") && format.len() > "strptime:".len() => {
            let format = &format["strptime:".len()..];
            jiff::fmt::strtime::format(
                format,
                &jiff::Timestamp::UNIX_EPOCH.to_zoned(jiff::tz::TimeZone::UTC),
            )
            .map_err(|error| Error::Config(format!("invalid strptime format: {error}")))?;
            Ok(TimestampFormat::Strptime(format.to_owned()))
        }
        format => Err(Error::Config(format!(
            "unsupported timestamp format {format:?}; expected rfc3339, unix, or strptime:<format>"
        ))),
    }
}

fn parse_timestamp(raw: &str, format: &TimestampFormat) -> Option<u64> {
    match format {
        TimestampFormat::Unix => raw.parse().ok(),
        TimestampFormat::Rfc3339 => raw
            .parse::<jiff::Timestamp>()
            .ok()
            .and_then(|timestamp| u64::try_from(timestamp.as_second()).ok()),
        TimestampFormat::Strptime(format) => {
            let parsed = jiff::fmt::strtime::parse(format, raw).ok()?;
            let timestamp = parsed.to_timestamp().ok().or_else(|| {
                parsed
                    .to_datetime()
                    .ok()?
                    .to_zoned(jiff::tz::TimeZone::system())
                    .ok()
                    .map(|zoned| zoned.timestamp())
            })?;
            u64::try_from(timestamp.as_second()).ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_prefilter_extracts_literal_ip() {
        let detector = CompiledDetector::new(&Detector::Regex {
            prefilter: Some(r"service: (?P<content>.*)".into()),
            patterns: vec![r"failed from (?P<address>[0-9.]+) on (?P<attempt_key>/[^ ]+)".into()],
            context_patterns: Vec::new(),
            max_context_lines: 0,
            context_window_secs: 120,
            ignore_patterns: Vec::new(),
            address_capture: "address".into(),
            timestamp_capture: None,
            timestamp_format: None,
        })
        .unwrap();
        assert_eq!(
            detector.detect("service: failed from 192.0.2.1 on /login", 42, None),
            Some(Detection {
                network: "192.0.2.1/32".parse().unwrap(),
                observed_at: 42,
                attempt_key: Some("/login".into()),
            })
        );
    }

    #[test]
    fn regex_context_is_bounded_and_keyed() {
        let detector = CompiledDetector::new(&Detector::Regex {
            prefilter: None,
            patterns: vec![r"direct from (?P<address>[0-9.]+)".into()],
            context_patterns: vec![
                r"(?s)^Connection from (?P<address>[0-9.]+) port[^\n]*\n(?:[^\n]*\n){0,2}Disconnecting: Too many authentication failures.*$".into(),
            ],
            max_context_lines: 3,
            context_window_secs: 120,
            ignore_patterns: Vec::new(),
            address_capture: "address".into(),
            timestamp_capture: None,
            timestamp_format: None,
        })
        .unwrap();

        assert_eq!(
            detector.detect("direct from 192.0.2.2", 39, None),
            Some(Detection {
                network: "192.0.2.2/32".parse().unwrap(),
                observed_at: 39,
                attempt_key: None,
            })
        );

        assert!(
            detector
                .detect("Connection from 192.0.2.3 port 1234", 40, Some("pid:1"))
                .is_none()
        );
        assert!(
            detector
                .detect(
                    "Disconnecting: Too many authentication failures for root [preauth]",
                    41,
                    Some("pid:2"),
                )
                .is_none()
        );
        assert_eq!(
            detector.detect(
                "Disconnecting: Too many authentication failures for root [preauth]",
                42,
                Some("pid:1"),
            ),
            Some(Detection {
                network: "192.0.2.3/32".parse().unwrap(),
                observed_at: 42,
                attempt_key: None,
            })
        );
    }

    #[test]
    fn json_predicates_reject_unrelated_events() {
        let detector = CompiledDetector::new(&Detector::Json {
            equals: BTreeMap::from([("/message".into(), "login failed".into())]),
            address_pointer: "/remoteAddr".into(),
            timestamp_pointer: None,
            timestamp_format: None,
        })
        .unwrap();
        assert!(
            detector
                .detect(
                    r#"{"message":"login ok","remoteAddr":"192.0.2.1"}"#,
                    42,
                    None,
                )
                .is_none()
        );
    }

    #[test]
    fn strptime_timestamps_use_the_system_timezone() {
        let format = parse_timestamp_format(Some("strptime:%Y/%m/%d %H:%M:%S")).unwrap();
        let parsed = parse_timestamp("2026/08/27 12:34:56", &format).unwrap();
        let expected = jiff::civil::DateTime::strptime("%Y/%m/%d %H:%M:%S", "2026/08/27 12:34:56")
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::system())
            .unwrap()
            .timestamp()
            .as_second();
        assert_eq!(parsed, u64::try_from(expected).unwrap());
        assert!(parse_timestamp_format(Some("strptime:%!")).is_err());
    }
}
