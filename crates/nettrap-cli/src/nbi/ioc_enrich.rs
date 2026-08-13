//! Shared indicator-of-compromise enrichment for HTTP-derived NBI events.
//!
//! Both the live HTTP listener and the offline PCAP-replay path attach IOCs
//! (domains, IPs, URLs, emails, hashes) extracted from attacker-controlled
//! request content. Keeping the extraction here ensures the two paths stay in
//! lock-step: a malware PCAP analyzed offline surfaces the same body IOCs the
//! live engine would have captured.

use nettrap_core::nbi::NetworkBehaviorIndicator;

/// Upper bound on request content scanned for indicators of compromise, so the
/// regex passes stay cheap even for large uploads.
pub(crate) const IOC_SCAN_LIMIT: usize = 16 * 1024;
/// Cap per IOC category to keep the recorded indicator values bounded.
pub(crate) const IOC_MAX_PER_CATEGORY: usize = 16;

/// Extract indicators of compromise from the attacker-controlled request
/// content (Host, request target, and a bounded prefix of the body) and attach
/// them to the captured event. Only these attacker-supplied fields are scanned
/// — never derived metadata such as JA3 hashes, whose hex digests would
/// otherwise be misread as MD5 IOCs.
pub(crate) fn enrich_nbi_with_iocs(
    nbi: &mut NetworkBehaviorIndicator,
    host: &str,
    target: &str,
    body: &[u8],
) {
    if let Err(err) = try_enrich_nbi_with_iocs(nbi, host, target, body) {
        tracing::error!("HTTP IOC enrichment failed: {err}");
    }
}

pub(crate) fn try_enrich_nbi_with_iocs(
    nbi: &mut NetworkBehaviorIndicator,
    host: &str,
    target: &str,
    body: &[u8],
) -> nettrap_ioc::ExtractResult<()> {
    let content = ioc_scan_content(host, target, body);

    add_ioc_indicator(
        nbi,
        "ioc_domains",
        nettrap_ioc::try_extract_domains(&content)?,
    );
    add_ioc_indicator(nbi, "ioc_ips", nettrap_ioc::try_extract_ipv4(&content)?);
    add_ioc_indicator(nbi, "ioc_urls", nettrap_ioc::try_extract_urls(&content)?);
    add_ioc_indicator(
        nbi,
        "ioc_emails",
        nettrap_ioc::try_extract_emails(&content)?,
    );
    let hashes: Vec<String> = nettrap_ioc::try_extract_hashes(&content)?
        .into_iter()
        .map(|(kind, value)| format!("{kind}:{value}"))
        .collect();
    add_ioc_indicator(nbi, "ioc_hashes", hashes);
    Ok(())
}

fn ioc_scan_content(host: &str, target: &str, body: &[u8]) -> String {
    let mut content = String::new();
    append_utf8_capped(&mut content, host);
    push_separator_capped(&mut content);
    append_utf8_capped(&mut content, target);
    push_separator_capped(&mut content);
    append_ascii_body_runs(&mut content, body);
    content
}

fn push_separator_capped(content: &mut String) {
    if content.len() < IOC_SCAN_LIMIT {
        content.push('\n');
    }
}

fn append_utf8_capped(content: &mut String, value: &str) {
    for ch in value.chars() {
        if content.len().saturating_add(ch.len_utf8()) > IOC_SCAN_LIMIT {
            return;
        }
        content.push(ch);
    }
}

fn append_ascii_body_runs(content: &mut String, body: &[u8]) {
    if content.len() >= IOC_SCAN_LIMIT {
        return;
    }

    let scan_len = body.len().min(IOC_SCAN_LIMIT);
    let mut start = 0usize;

    while start < scan_len && content.len() < IOC_SCAN_LIMIT {
        while start < scan_len && !body[start].is_ascii() {
            start += 1;
        }
        let run_start = start;
        while start < scan_len && body[start].is_ascii() {
            start += 1;
        }
        if run_start < start {
            push_separator_capped(content);
            let remaining = IOC_SCAN_LIMIT.saturating_sub(content.len());
            let end = run_start + remaining.min(start - run_start);
            content.push_str(std::str::from_utf8(&body[run_start..end]).unwrap_or_default());
        }
    }
}

pub(crate) fn add_ioc_indicator(
    nbi: &mut NetworkBehaviorIndicator,
    key: &str,
    mut values: Vec<String>,
) {
    if values.is_empty() {
        return;
    }
    values.sort();
    values.dedup();
    values.truncate(IOC_MAX_PER_CATEGORY);
    nbi.add(key, values.join(","));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriches_http_body_iocs() {
        let mut nbi =
            NetworkBehaviorIndicator::new("t", "HTTP", "203.0.113.5", 40000, "198.51.100.9", 80);
        let body = b"domain=download.evil-payload.net ip=45.33.32.156 \
            url=https://cdn.badactor.com/loader.exe?id=99 \
            md5=d41d8cd98f00b204e9800998ecf8427e \
            email=operator@exfil-mail.org";
        enrich_nbi_with_iocs(&mut nbi, "c2.malware-domain.io", "/exfil", body);

        let indicators = &nbi.indicators;
        assert!(
            indicators
                .get("ioc_domains")
                .is_some_and(|v| v.contains("download.evil-payload.net")),
            "body domain must be extracted: {indicators:?}"
        );
        assert!(
            indicators
                .get("ioc_ips")
                .is_some_and(|v| v.contains("45.33.32.156")),
            "body IP must be extracted"
        );
        assert!(
            indicators
                .get("ioc_urls")
                .is_some_and(|v| v.contains("https://cdn.badactor.com/loader.exe")),
            "body URL must be extracted"
        );
        assert!(
            indicators
                .get("ioc_emails")
                .is_some_and(|v| v.contains("operator@exfil-mail.org")),
            "body email must be extracted"
        );
        assert!(
            indicators
                .get("ioc_hashes")
                .is_some_and(|v| v.contains("md5:d41d8cd98f00b204e9800998ecf8427e")),
            "body hash must be extracted"
        );
    }

    #[test]
    fn empty_categories_are_omitted() {
        let mut nbi = NetworkBehaviorIndicator::new("t", "HTTP", "1.1.1.1", 1, "2.2.2.2", 2);
        enrich_nbi_with_iocs(&mut nbi, "", "/", b"no indicators here");
        assert!(!nbi.indicators.contains_key("ioc_domains"));
        assert!(!nbi.indicators.contains_key("ioc_hashes"));
    }

    #[test]
    fn enriches_http_body_iocs_from_ascii_runs_inside_binary_body() {
        let mut nbi =
            NetworkBehaviorIndicator::new("t", "HTTP", "203.0.113.5", 40000, "198.51.100.9", 80);
        let body = b"\xffdomain=download.evil-payload.net\x00ip=45.33.32.156\xff";

        enrich_nbi_with_iocs(&mut nbi, "", "/exfil", body);

        assert!(
            nbi.indicators
                .get("ioc_domains")
                .is_some_and(|v| v.contains("download.evil-payload.net"))
        );
        assert!(
            nbi.indicators
                .get("ioc_ips")
                .is_some_and(|v| v.contains("45.33.32.156"))
        );
    }

    #[test]
    fn ioc_scan_content_bounds_host_target_and_body_together() {
        let host = "h".repeat(IOC_SCAN_LIMIT + 256);
        let target = "/download.evil.example";
        let body = b"ip=45.33.32.156";

        let content = ioc_scan_content(&host, target, body);

        assert_eq!(content.len(), IOC_SCAN_LIMIT);
        assert!(!content.contains("download.evil.example"));
        assert!(!content.contains("45.33.32.156"));
    }
}
