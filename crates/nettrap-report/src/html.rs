use crate::prelude::*;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn generate_html_report(report: &Report) -> Result<String> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n");
    html.push_str("<head>\n");
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("  <title>NetTrap Report</title>\n");
    html.push_str("  <style>\n");
    html.push_str("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }\n");
    html.push_str("    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
    html.push_str(
        "    h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n",
    );
    html.push_str("    h2 { color: #555; margin-top: 30px; }\n");
    html.push_str("    table { width: 100%; border-collapse: collapse; margin-top: 10px; }\n");
    html.push_str(
        "    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n",
    );
    html.push_str("    th { background-color: #4CAF50; color: white; }\n");
    html.push_str("    tr:hover { background-color: #f5f5f5; }\n");
    html.push_str("    .meta { color: #666; font-size: 14px; margin-bottom: 20px; }\n");
    html.push_str("    .ioc-high { color: #d32f2f; font-weight: bold; }\n");
    html.push_str("    .ioc-medium { color: #ff9800; }\n");
    html.push_str("    .ioc-low { color: #4caf50; }\n");
    html.push_str("  </style>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");
    html.push_str("  <div class=\"container\">\n");

    html.push_str(&format!("    <h1>{}</h1>\n", report.title));
    html.push_str(&format!(
        "    <div class=\"meta\">Generated: {}</div>\n",
        report.generated_at
    ));

    html.push_str("    <h2>Network Flows</h2>\n");
    html.push_str("    <p>Total flows: ");
    html.push_str(&report.flows.len().to_string());
    html.push_str("</p>\n");
    html.push_str("    <table>\n");
    html.push_str("      <tr><th>Flow ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes Sent</th><th>Bytes Received</th><th>Duration (ms)</th><th>Process</th></tr>\n");

    for flow in &report.flows {
        html.push_str("      <tr>\n");
        html.push_str(&format!(
            "        <td>{}</td>\n",
            html_escape(&flow.flow_id)
        ));
        html.push_str(&format!("        <td>{}</td>\n", html_escape(&flow.src)));
        html.push_str(&format!("        <td>{}</td>\n", html_escape(&flow.dst)));
        html.push_str(&format!(
            "        <td>{}</td>\n",
            html_escape(&flow.protocol)
        ));
        html.push_str(&format!("        <td>{}</td>\n", flow.bytes_sent));
        html.push_str(&format!("        <td>{}</td>\n", flow.bytes_received));
        html.push_str(&format!("        <td>{}</td>\n", flow.duration_ms));
        html.push_str(&format!(
            "        <td>{}</td>\n",
            html_escape(flow.process.as_deref().unwrap_or("-"))
        ));
        html.push_str("      </tr>\n");
    }

    html.push_str("    </table>\n");

    html.push_str("    <h2>Events</h2>\n");
    html.push_str("    <p>Total events: ");
    html.push_str(&report.events.len().to_string());
    html.push_str("</p>\n");

    if !report.events.is_empty() {
        html.push_str("    <table>\n");
        html.push_str("      <tr><th>Timestamp</th><th>Type</th><th>Summary</th></tr>\n");

        for event in &report.events {
            html.push_str("      <tr>\n");
            html.push_str(&format!("        <td>{}</td>\n", event.timestamp));
            html.push_str(&format!(
                "        <td>{}</td>\n",
                html_escape(&event.event_type)
            ));
            html.push_str(&format!(
                "        <td>{}</td>\n",
                html_escape(&event.summary)
            ));
            html.push_str("      </tr>\n");
        }

        html.push_str("    </table>\n");
    }

    html.push_str("    <h2>Indicators of Compromise</h2>\n");
    html.push_str("    <p>Total IoCs: ");
    html.push_str(&report.iocs.len().to_string());
    html.push_str("</p>\n");

    if !report.iocs.is_empty() {
        html.push_str("    <table>\n");
        html.push_str(
            "      <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Source</th></tr>\n",
        );

        for ioc in &report.iocs {
            html.push_str("      <tr>\n");
            html.push_str(&format!(
                "        <td>{}</td>\n",
                html_escape(&ioc.ioc_type)
            ));
            html.push_str(&format!("        <td>{}</td>\n", html_escape(&ioc.value)));

            let confidence_class = if ioc.confidence >= 0.8 {
                "ioc-high"
            } else if ioc.confidence >= 0.5 {
                "ioc-medium"
            } else {
                "ioc-low"
            };
            html.push_str(&format!(
                "        <td class=\"{}\">{:.1}%</td>\n",
                confidence_class,
                ioc.confidence * 100.0
            ));
            html.push_str(&format!("        <td>{}</td>\n", html_escape(&ioc.source)));
            html.push_str("      </tr>\n");
        }

        html.push_str("    </table>\n");
    }

    html.push_str("  </div>\n");
    html.push_str("</body>\n");
    html.push_str("</html>\n");

    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_html_report_includes_events_section() {
        let report = Report {
            title: "NetTrap Report".to_string(),
            generated_at: now(),
            flows: Vec::new(),
            events: vec![EventSummary {
                event_type: "http_request".to_string(),
                timestamp: now(),
                summary: "GET /hello?<script>".to_string(),
            }],
            iocs: Vec::new(),
        };

        let html = generate_html_report(&report).expect("html report should render");

        assert!(html.contains("Events"));
        assert!(html.contains("Total events: 1"));
        assert!(html.contains("http_request"));
        assert!(html.contains("GET /hello?&lt;script&gt;"));
    }
}
