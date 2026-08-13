use super::NbiCollector;
use nettrap_core::NetworkBehaviorIndicator;
use nettrap_fsutil::create_regular_file;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn load_report_nbis(
    nbi_jsonl_path: &std::path::Path,
) -> std::io::Result<Vec<NetworkBehaviorIndicator>> {
    std::fs::metadata(nbi_jsonl_path).map_err(|err| {
        std::io::Error::other(format!(
            "failed to read NBI input '{}': {}",
            nbi_jsonl_path.display(),
            err
        ))
    })?;

    let loaded = crate::output::load_nbis_from_jsonl_detailed(nbi_jsonl_path);
    if let Some(read_error) = loaded.read_error {
        return Err(std::io::Error::other(format!(
            "failed to read NBI input '{}': {}",
            nbi_jsonl_path.display(),
            read_error
        )));
    }
    if loaded.invalid_lines > 0 {
        return Err(std::io::Error::other(format!(
            "failed to read NBI input '{}': {} invalid NBI JSONL lines",
            nbi_jsonl_path.display(),
            loaded.invalid_lines
        )));
    }

    Ok(loaded.events)
}

/// Print NBI summary to console
pub fn print_summary(nbi_jsonl_path: &std::path::Path) -> std::io::Result<()> {
    let events = load_report_nbis(nbi_jsonl_path)?;
    print_summary_from_events(&events);
    Ok(())
}

pub fn print_summary_from_events(nbis: &[NetworkBehaviorIndicator]) {
    let mut protocol_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    for nbi in nbis {
        *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
        unique_ips.insert(nbi.src_ip.clone());
    }

    if nbis.is_empty() {
        return;
    }

    println!("\n=== NetTrap NBI Summary ===");
    println!("Total events:    {}", nbis.len());
    println!("Unique sources:  {}", unique_ips.len());
    println!("Protocols:");
    let mut sorted: Vec<_> = protocol_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in sorted {
        println!("  {:<10} {}", proto, count);
    }
    println!("===========================\n");
}

impl NbiCollector {
    /// Generate an HTML report from the NBI JSONL file
    pub fn generate_html_report(
        nbi_jsonl_path: &std::path::Path,
        output_path: &std::path::Path,
        lang: &str,
    ) -> std::io::Result<()> {
        let nbis = load_report_nbis(nbi_jsonl_path)?;
        Self::generate_html_report_from_events(&nbis, output_path, lang)
    }

    pub fn generate_html_report_from_events(
        nbis: &[NetworkBehaviorIndicator],
        output_path: &std::path::Path,
        lang: &str,
    ) -> std::io::Result<()> {
        use crate::i18n::t;
        let translate = |key: &'static str| -> std::io::Result<&'static str> {
            t(key, lang).map_err(|err| std::io::Error::other(err.to_string()))
        };
        let title = translate("report_title")?;
        let title_escaped = html_escape(title);
        let mut html = format!(
            r#"<!DOCTYPE html>
<html><head>
<title>{}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}
h1 {{ color: #d35400; border-bottom: 2px solid #d35400; padding-bottom: 10px; }}
h2 {{ color: #2c3e50; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
th {{ background: #2c3e50; color: white; padding: 10px 15px; text-align: left; }}
td {{ padding: 8px 15px; border-bottom: 1px solid #ecf0f1; }}
tr:hover {{ background: #f8f9fa; }}
.summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }}
.card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); min-width: 150px; }}
.card h3 {{ margin: 0 0 10px 0; color: #7f8c8d; font-size: 14px; }}
.card .value {{ font-size: 28px; font-weight: bold; color: #2c3e50; }}
.protocol-dns {{ color: #2980b9; }} .protocol-http {{ color: #27ae60; }}
.protocol-smtp {{ color: #8e44ad; }} .protocol-ftp {{ color: #d35400; }}
.protocol-pop3 {{ color: #c0392b; }} .protocol-irc {{ color: #16a085; }}
.protocol-tls {{ color: #f39c12; }} .protocol-raw {{ color: #7f8c8d; }}
.protocol-tftp {{ color: #2c3e50; }}
.indicators {{ font-family: monospace; font-size: 12px; }}
</style>
</head><body>
<h1>{}</h1>
"#,
            title_escaped, title_escaped
        );

        let total = nbis.len();
        let mut protocol_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for nbi in nbis {
            *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
            unique_ips.insert(nbi.src_ip.clone());
        }

        html.push_str("<div class=\"summary\">");
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            translate("total_events")?,
            total
        ));
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            translate("unique_sources")?,
            unique_ips.len()
        ));
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            translate("protocols")?,
            protocol_counts.len()
        ));
        html.push_str("</div>");

        html.push_str(&format!(
            "<h2>{}</h2><table><tr><th>{}</th><th>{}</th></tr>",
            translate("protocol_summary")?,
            translate("protocol")?,
            translate("events")?
        ));
        let mut sorted_protos: Vec<_> = protocol_counts.iter().collect();
        sorted_protos.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in &sorted_protos {
            html.push_str(&format!(
                "<tr><td class=\"protocol-{}\">{}</td><td>{}</td></tr>",
                html_escape(&proto.to_lowercase()),
                html_escape(proto),
                count
            ));
        }
        html.push_str("</table>");

        html.push_str(&format!(
            "<h2>{}</h2><table><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>",
            translate("all_events")?,
            translate("time")?,
            translate("protocol")?,
            translate("listener")?,
            translate("source")?,
            translate("destination")?,
            translate("port")?,
            translate("indicators")?,
            translate("process")?
        ));
        for nbi in nbis {
            let indicators_str: String = nbi
                .indicators
                .iter()
                .map(|(k, v)| format!("{}={}", html_escape(k), html_escape(v)))
                .collect::<Vec<_>>()
                .join(", ");
            let process_str = match (&nbi.process_name, &nbi.process_pid) {
                (Some(name), Some(pid)) => format!("{} ({})", html_escape(name), pid),
                (Some(name), None) => html_escape(name),
                _ => String::new(),
            };
            let timestamp_display: String = nbi.timestamp.chars().take(19).collect();
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"protocol-{}\">{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td class=\"indicators\">{}</td><td>{}</td></tr>",
                html_escape(&timestamp_display),
                html_escape(&nbi.protocol.to_lowercase()), html_escape(&nbi.protocol), html_escape(&nbi.listener),
                html_escape(&nbi.src_ip), nbi.src_port, html_escape(&nbi.dst_ip), nbi.dst_port, indicators_str, process_str
            ));
        }
        html.push_str("</table>");

        html.push_str(&format!(
            "<p><em>{} - {}</em></p>",
            translate("generated_by")?,
            crate::faketime::fake_now().to_rfc3339()
        ));
        html.push_str("</body></html>");

        use std::io::Write;

        let mut file = create_regular_file(output_path)?;
        file.write_all(html.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_summary_returns_read_error_for_missing_input() {
        let missing_path = std::env::temp_dir().join(format!(
            "nettrap-missing-nbi-{}.jsonl",
            uuid::Uuid::new_v4()
        ));

        let err = print_summary(&missing_path).expect_err("missing file should fail");

        assert!(
            err.to_string().contains("failed to read NBI input"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn print_summary_rejects_invalid_jsonl_lines() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-invalid-nbi-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            concat!(
                r#"{"event_id":"1","listener":"raw","protocol":"RAW","src_ip":"127.0.0.1","src_port":1,"dst_ip":"127.0.0.1","dst_port":2,"process_name":null,"process_pid":null,"indicators":{},"timestamp":"2024-01-01T00:00:00Z"}"#,
                "\n",
                r#"{"not":"an nbi"}"#,
                "\n",
            ),
        )
        .expect("test file should write");

        let err = print_summary(&path).expect_err("invalid JSONL should fail");

        assert!(
            err.to_string().contains("invalid NBI JSONL lines"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn generate_html_report_from_events_creates_missing_parent_directory() {
        let temp_dir =
            std::env::temp_dir().join(format!("nettrap-html-report-{}", uuid::Uuid::new_v4()));
        let output_path = temp_dir.join("nested/report.html");
        let event =
            NetworkBehaviorIndicator::new("listener", "HTTP", "127.0.0.1", 12345, "127.0.0.1", 80);

        let result = NbiCollector::generate_html_report_from_events(&[event], &output_path, "en");

        assert!(
            result.is_ok(),
            "report generation should create parent directories"
        );
        assert!(output_path.exists(), "report file should be written");

        let _ = std::fs::remove_file(&output_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn generate_html_report_from_events_uses_faketime_offset_for_footer() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);

        let temp_dir =
            std::env::temp_dir().join(format!("nettrap-html-report-time-{}", uuid::Uuid::new_v4()));
        let output_path = temp_dir.join("report.html");
        let event =
            NetworkBehaviorIndicator::new("listener", "HTTP", "127.0.0.1", 12345, "127.0.0.1", 80);

        NbiCollector::generate_html_report_from_events(&[event], &output_path, "en")
            .expect("report generation should succeed");

        let html = std::fs::read_to_string(&output_path).expect("report should be readable");
        let expected_date = crate::faketime::fake_now().date_naive().to_string();
        assert!(
            html.contains(&expected_date),
            "report footer should use faketime offset"
        );

        crate::faketime::set_delta(baseline);
        let _ = std::fs::remove_file(&output_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
