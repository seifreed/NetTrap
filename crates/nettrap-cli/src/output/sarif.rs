//! SARIF v2.1.0 export for NBI events.

use super::event_time_bounds;
use super::write_atomically;
use crate::nbi::NetworkBehaviorIndicator;
use serde::Serialize;
use std::path::Path;

const SARIF_MESSAGE_FIELD_PREVIEW_CHARS: usize = 240;
const SARIF_MESSAGE_MAX_INDICATORS: usize = 32;

pub(crate) fn export_sarif(
    events: &[NetworkBehaviorIndicator],
    path: &Path,
) -> std::io::Result<()> {
    let (start_time_utc, end_time_utc) = event_time_bounds(events);
    let results: Vec<SarifResult> = events
        .iter()
        .map(|e| {
            let level = match e.protocol.as_str() {
                "RAW" | "SMTP" | "FTP" | "POP3" | "IRC" => "note",
                _ => "warning",
            };

            let rule_id = format!("NT-{}-001", e.protocol.to_uppercase());

            let indicators_str = sarif_indicator_message(&e.indicators);

            let message = if indicators_str.is_empty() {
                format!(
                    "{} event from {}:{} to {}:{}",
                    sarif_message_field(&e.protocol),
                    sarif_message_field(&e.src_ip),
                    e.src_port,
                    sarif_message_field(&e.dst_ip),
                    e.dst_port
                )
            } else {
                format!(
                    "{} event from {}:{} to {}:{} - {}",
                    sarif_message_field(&e.protocol),
                    sarif_message_field(&e.src_ip),
                    e.src_port,
                    sarif_message_field(&e.dst_ip),
                    e.dst_port,
                    indicators_str
                )
            };

            SarifResult {
                rule_id,
                level: level.to_string(),
                message: SarifMessage { text: message },
                locations: vec![SarifLocation {
                    logical_locations: vec![SarifLogicalLocation {
                        fully_qualified_name: format!(
                            "{}:{} -> {}:{}",
                            e.src_ip, e.src_port, e.dst_ip, e.dst_port
                        ),
                    }],
                }],
                properties: SarifProperties {
                    event_id: e.event_id.clone(),
                    timestamp: e.timestamp.clone(),
                    listener: e.listener.clone(),
                    protocol: e.protocol.clone(),
                    src_ip: e.src_ip.clone(),
                    src_port: e.src_port,
                    dst_ip: e.dst_ip.clone(),
                    dst_port: e.dst_port,
                    process_name: e.process_name.clone(),
                    process_pid: e.process_pid,
                    indicators: e.indicators.clone(),
                },
            }
        })
        .collect();

    let mut rules: Vec<SarifRule> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    for r in &results {
        if seen_rules.insert(r.rule_id.clone()) {
            let proto = r.properties.protocol.clone();
            rules.push(SarifRule {
                id: r.rule_id.clone(),
                name: format!("{} Network Event", proto),
                short_description: SarifMessage {
                    text: format!("{} protocol activity detected by NetTrap", proto),
                },
            });
        }
    }

    let sarif = SarifDocument {
        schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "NetTrap".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/seifreed/NetTrap".to_string(),
                    rules,
                },
            },
            invocations: vec![SarifInvocation {
                execution_successful: true,
                start_time_utc,
                end_time_utc,
            }],
            results,
        }],
    };

    use std::io::Write;

    write_atomically(path, |file| {
        let json = serde_json::to_string_pretty(&sarif).map_err(std::io::Error::other)?;
        file.write_all(json.as_bytes())
    })
}

fn sarif_indicator_message(indicators: &std::collections::BTreeMap<String, String>) -> String {
    let mut fields: Vec<_> = indicators.iter().collect();
    fields.sort_unstable_by(|left, right| left.0.cmp(right.0));

    let mut rendered = fields
        .iter()
        .take(SARIF_MESSAGE_MAX_INDICATORS)
        .map(|(key, value)| {
            format!(
                "{}={}",
                sarif_message_field(key),
                sarif_message_field(value)
            )
        })
        .collect::<Vec<_>>();

    if fields.len() > SARIF_MESSAGE_MAX_INDICATORS {
        rendered.push(format!(
            "{} more indicators omitted",
            fields.len() - SARIF_MESSAGE_MAX_INDICATORS
        ));
    }

    rendered.join(", ")
}

fn sarif_message_field(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
        .chars()
        .take(SARIF_MESSAGE_FIELD_PREVIEW_CHARS)
        .collect()
}

#[derive(Serialize)]
struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    invocations: Vec<SarifInvocation>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    start_time_utc: String,
    end_time_utc: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    fully_qualified_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifProperties {
    event_id: String,
    timestamp: String,
    listener: String,
    protocol: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    process_name: Option<String>,
    process_pid: Option<u32>,
    // BTreeMap mirrors NetworkBehaviorIndicator::indicators so SARIF output is
    // deterministic (sorted keys) across identical runs.
    indicators: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: identical input must yield byte-identical SARIF. NBI
    /// indicators were once a HashMap, whose randomized iteration order made
    /// report output (and the SARIF message text) differ between runs, breaking
    /// diffing/fingerprinting in downstream tooling.
    #[test]
    fn sarif_export_is_deterministic_across_runs() {
        let mut event =
            NetworkBehaviorIndicator::new("http", "HTTP", "203.0.113.5", 40000, "198.51.100.9", 80);
        // Many indicators so a randomized map order would almost certainly differ.
        for (k, v) in [
            ("uri", "/a.exe"),
            ("host", "evil.test"),
            ("method", "GET"),
            ("user_agent", "curl/8"),
            ("ioc_domains", "evil.test,cdn.bad.net"),
            ("ioc_ips", "45.33.32.156"),
            ("ioc_urls", "https://cdn.bad.net/x"),
            ("ioc_hashes", "md5:d41d8cd98f00b204e9800998ecf8427e"),
            ("ioc_emails", "a@bad.test"),
            ("body_length", "123"),
        ] {
            event.add(k, v);
        }
        let events = vec![event];

        let dir = std::env::temp_dir();
        let mut digests = std::collections::HashSet::new();
        for i in 0..8 {
            let path = dir.join(format!(
                "nettrap-sarif-determinism-{}-{}.json",
                std::process::id(),
                i
            ));
            export_sarif(&events, &path).expect("export sarif");
            let bytes = std::fs::read(&path).expect("read sarif");
            digests.insert(bytes);
            let _ = std::fs::remove_file(&path);
        }
        assert_eq!(
            digests.len(),
            1,
            "SARIF export must be byte-identical across runs"
        );
    }

    #[test]
    fn sarif_export_uses_the_package_version_for_the_driver_metadata() {
        let event =
            NetworkBehaviorIndicator::new("http", "HTTP", "203.0.113.5", 40000, "198.51.100.9", 80);
        let path =
            std::env::temp_dir().join(format!("nettrap-sarif-version-{}.json", std::process::id()));

        export_sarif(&[event], &path).expect("export sarif");
        let sarif: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read sarif"))
                .expect("parse sarif");
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }
}
