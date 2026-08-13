//! CSV export for NBI events.

use super::write_atomically;
use crate::nbi::NetworkBehaviorIndicator;
use std::path::Path;

pub(crate) fn export_csv(events: &[NetworkBehaviorIndicator], path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    write_atomically(path, |file| {
        // Collect all possible indicator keys
        let mut all_keys: Vec<String> = Vec::new();
        for e in events {
            for key in e.indicators.keys() {
                if !all_keys.contains(key) {
                    all_keys.push(key.clone());
                }
            }
        }
        all_keys.sort();

        // Write CSV header
        let header_parts = vec![
            "event_id",
            "timestamp",
            "listener",
            "protocol",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "process_name",
            "process_pid",
        ];
        let escaped_keys: Vec<String> = all_keys.iter().map(|s| csv_escape(s)).collect();
        let header_line: Vec<&str> = header_parts
            .iter()
            .copied()
            .chain(escaped_keys.iter().map(|s| s.as_str()))
            .collect();
        writeln!(file, "{}", header_line.join(","))?;

        for e in events {
            let mut row = vec![
                csv_escape(&e.event_id),
                csv_escape(&e.timestamp),
                csv_escape(&e.listener),
                csv_escape(&e.protocol),
                csv_escape(&e.src_ip),
                e.src_port.to_string(),
                csv_escape(&e.dst_ip),
                e.dst_port.to_string(),
                csv_escape(&e.process_name.clone().unwrap_or_default()),
                e.process_pid.map(|p| p.to_string()).unwrap_or_default(),
            ];
            for key in &all_keys {
                row.push(csv_escape(
                    &e.indicators.get(key).cloned().unwrap_or_default(),
                ));
            }
            writeln!(file, "{}", row.join(","))?;
        }

        Ok(())
    })
}

pub(crate) fn csv_escape(value: &str) -> String {
    let escaped = csv_field_content(value);
    let needs_formula_guard = needs_formula_guard(value);
    if needs_formula_guard
        || escaped != value
        || escaped.contains(',')
        || escaped.contains('"')
        || escaped.contains('\n')
        || escaped.contains('\r')
    {
        let escaped_quotes = escaped.replace('"', "\"\"");
        if needs_formula_guard {
            format!("\"'{}\"", escaped_quotes)
        } else {
            format!("\"{}\"", escaped_quotes)
        }
    } else {
        escaped
    }
}

fn csv_field_content(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::new();
    for ch in value.chars() {
        if (ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
            || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
        {
            let _ = write!(escaped, "\\u{:04X}", ch as u32);
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn needs_formula_guard(value: &str) -> bool {
    let trimmed = value.trim_start_matches(char::is_whitespace);
    matches!(trimmed.as_bytes().first(), Some(b'=' | b'+' | b'-' | b'@'))
}
