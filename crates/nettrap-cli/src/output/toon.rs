//! TOON (Token-Oriented Object Notation) export for NBI events.

use super::event_time_bounds;
use super::write_atomically;
use crate::nbi::NetworkBehaviorIndicator;
use std::path::Path;

pub(crate) fn export_toon(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    write_atomically(path, |file| {
        let (start, end) = event_time_bounds(events);

        // Header
        writeln!(file, "capture:")?;
        writeln!(file, "  tool: {}", toon_string_value("NetTrap"))?;
        writeln!(
            file,
            "  version: {}",
            toon_string_value(env!("CARGO_PKG_VERSION"))
        )?;
        if !start.is_empty() {
            writeln!(file, "  start: {}", toon_string_value(&start))?;
        }
        if !end.is_empty() {
            writeln!(file, "  end: {}", toon_string_value(&end))?;
        }
        writeln!(file, "  total_events: {}", events.len())?;

        let mut by_protocol: std::collections::BTreeMap<String, Vec<&NetworkBehaviorIndicator>> =
            std::collections::BTreeMap::new();
        for event in events {
            by_protocol
                .entry(event.protocol.clone())
                .or_default()
                .push(event);
        }

        // Write each protocol group as a TOON tabular array
        for (protocol, proto_events) in &by_protocol {
            let mut all_keys: Vec<String> = Vec::new();
            for e in proto_events {
                for key in e.indicators.keys() {
                    if !all_keys.contains(key) {
                        all_keys.push(key.clone());
                    }
                }
            }
            all_keys.sort();

            // Build column headers: timestamp, listener, src_ip, src_port, dst_ip, dst_port, [indicator keys...]
            let mut columns = vec![
                "timestamp".to_string(),
                "listener".to_string(),
                "src_ip".to_string(),
                "src_port".to_string(),
                "dst_ip".to_string(),
                "dst_port".to_string(),
            ];
            if proto_events.iter().any(|e| e.process_name.is_some()) {
                columns.push("process".to_string());
            }
            columns.extend(all_keys.iter().cloned());

            let header = columns
                .iter()
                .map(|column| toon_key(column))
                .collect::<Vec<_>>()
                .join(",");
            let group_key = toon_key(&format!("{}_events", protocol.to_lowercase()));
            writeln!(file, "{}[{}]{{{}}}:", group_key, proto_events.len(), header)?;

            let include_process = columns.iter().any(|column| column == "process");
            for e in proto_events {
                let mut row = vec![
                    toon_string_value(&e.timestamp),
                    toon_string_value(&e.listener),
                    toon_string_value(&e.src_ip),
                    e.src_port.to_string(),
                    toon_string_value(&e.dst_ip),
                    e.dst_port.to_string(),
                ];
                if include_process {
                    row.push(toon_string_value(
                        e.process_name.as_deref().unwrap_or_default(),
                    ));
                }
                for key in &all_keys {
                    row.push(toon_string_value(
                        e.indicators.get(key).map_or("", String::as_str),
                    ));
                }
                writeln!(file, "  {}", row.join(","))?;
            }
        }

        Ok(())
    })
}

fn toon_key(key: &str) -> String {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return "\"\"".to_string();
    };

    if (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
    {
        key.to_string()
    } else {
        format!("\"{}\"", toon_quoted_content(key))
    }
}

fn toon_string_value(value: &str) -> String {
    if toon_string_needs_quotes(value) {
        format!("\"{}\"", toon_quoted_content(value))
    } else {
        value.to_string()
    }
}

fn toon_string_needs_quotes(value: &str) -> bool {
    value.is_empty()
        || value == "true"
        || value == "false"
        || value == "null"
        || value.starts_with('-')
        || toon_numeric_like(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.chars().any(|ch| {
            matches!(
                ch,
                ',' | ':'
                    | '"'
                    | '\\'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '\n'
                    | '\r'
                    | '\t'
                    | '\u{0085}'
                    | '\u{2028}'
                    | '\u{2029}'
            ) || ch.is_whitespace()
                || ch.is_control()
        })
}

fn toon_numeric_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = usize::from(bytes.first() == Some(&b'-'));
    let digits_start = idx;
    while bytes.get(idx).is_some_and(u8::is_ascii_digit) {
        idx += 1;
    }
    if idx == digits_start {
        return false;
    }

    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        let fraction_start = idx;
        while bytes.get(idx).is_some_and(u8::is_ascii_digit) {
            idx += 1;
        }
        if idx == fraction_start {
            return false;
        }
    }

    if matches!(bytes.get(idx), Some(b'e' | b'E')) {
        idx += 1;
        if matches!(bytes.get(idx), Some(b'+' | b'-')) {
            idx += 1;
        }
        let exponent_start = idx;
        while bytes.get(idx).is_some_and(u8::is_ascii_digit) {
            idx += 1;
        }
        if idx == exponent_start {
            return false;
        }
    }

    idx == bytes.len()
}

fn toon_quoted_content(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{0085}' => escaped.push_str("\\u0085"),
            '\u{2028}' => escaped.push_str("\\u2028"),
            '\u{2029}' => escaped.push_str("\\u2029"),
            ch if ch.is_control() => {
                let _ = write!(escaped, "\\u{:04X}", ch as u32);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{export_toon, toon_key, toon_string_value};
    use crate::nbi::NetworkBehaviorIndicator;
    use std::path::Path;

    #[test]
    fn toon_string_value_escapes_unicode_line_separators() {
        assert_eq!(
            toon_string_value("alpha\u{2028}beta"),
            "\"alpha\\u2028beta\""
        );
        assert_eq!(
            toon_string_value("alpha\u{2029}beta"),
            "\"alpha\\u2029beta\""
        );
        assert_eq!(
            toon_string_value("alpha\u{0085}beta"),
            "\"alpha\\u0085beta\""
        );
    }

    #[test]
    fn toon_string_value_quotes_internal_ascii_whitespace() {
        assert_eq!(toon_string_value("hello world"), "\"hello world\"");
        assert_eq!(toon_string_value("hello\tworld"), "\"hello\\tworld\"");
    }

    #[test]
    fn toon_key_escapes_unicode_line_separators() {
        assert_eq!(toon_key("control\u{2028}key"), "\"control\\u2028key\"");
        assert_eq!(toon_key("control\u{2029}key"), "\"control\\u2029key\"");
        assert_eq!(toon_key("control\u{0085}key"), "\"control\\u0085key\"");
    }

    #[test]
    fn export_toon_uses_the_package_version_in_the_header() {
        let event =
            NetworkBehaviorIndicator::new("http", "HTTP", "203.0.113.5", 40000, "198.51.100.9", 80);
        let path =
            std::env::temp_dir().join(format!("nettrap-toon-version-{}.toon", std::process::id()));

        export_toon(&[event], Path::new(&path)).expect("export toon");
        let output = std::fs::read_to_string(&path).expect("read toon");
        let _ = std::fs::remove_file(&path);

        assert!(output.contains(env!("CARGO_PKG_VERSION")));
    }
}
