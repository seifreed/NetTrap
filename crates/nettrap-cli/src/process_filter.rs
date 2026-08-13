use std::sync::Arc;

use nettrap_core::sanitize::trim_ascii_spaces_tabs as trim_ascii_edges;

/// Process filter supporting literal substring patterns and explicit regex patterns.
///
/// Used to determine if a process should be allowed to interact with a listener.
/// Supports both global filters (shared across all listeners) and per-listener
/// filters (specific to a single listener configuration).
///
/// # Filter Evaluation Order
///
/// 1. If global whitelist is non-empty, process must match at least one pattern
/// 2. If global blacklist is non-empty, process must not match any pattern
/// 3. If per-listener whitelist is non-empty, process must match at least one pattern
/// 4. If per-listener blacklist is non-empty, process must not match any pattern
/// 5. Otherwise, process is allowed
///
/// # Security Note
///
/// Patterns are literal, case-insensitive substrings by default. Prefix a pattern
/// with `re:` or `regex:` to opt into regex matching.
#[derive(Clone)]
pub struct ProcessFilter {
    global_whitelist: Arc<Vec<PatternMatcher>>,
    global_blacklist: Arc<Vec<PatternMatcher>>,
    per_listener_whitelist: Vec<PatternMatcher>,
    per_listener_blacklist: Vec<PatternMatcher>,
}

/// Compiled process-name pattern.
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    original: String,
    strategy: PatternStrategy,
}

#[derive(Debug, Clone)]
enum PatternStrategy {
    Literal { needle: String },
    Regex(regex::Regex),
}

impl PatternMatcher {
    /// Creates a new pattern matcher from a string pattern.
    ///
    /// Patterns are literal, case-insensitive substrings unless they use the
    /// `re:` or `regex:` prefix. Blank patterns and invalid explicit regex
    /// patterns return an error.
    pub fn new(pattern: &str) -> crate::Result<Self> {
        let pattern = trim_ascii_edges(pattern);
        let is_blank_pattern = pattern.is_empty()
            || pattern
                .chars()
                .all(|ch| ch.is_whitespace() || ch.is_control());

        if is_blank_pattern {
            return Err(crate::Error::Config(
                "Process filter pattern must not be blank".to_string(),
            ));
        }

        let strategy = if let Some(regex_pattern) = pattern
            .strip_prefix("re:")
            .or_else(|| pattern.strip_prefix("regex:"))
        {
            if regex_pattern.is_empty() {
                return Err(crate::Error::Config(
                    "Process filter regex pattern must not be blank".to_string(),
                ));
            }

            match regex::Regex::new(regex_pattern) {
                Ok(regex) => PatternStrategy::Regex(regex),
                Err(err) => {
                    return Err(crate::Error::Config(format!(
                        "Invalid process filter regex '{}': {}",
                        pattern, err
                    )));
                }
            }
        } else {
            PatternStrategy::Literal {
                needle: pattern.to_lowercase(),
            }
        };

        Ok(Self {
            original: pattern.to_string(),
            strategy,
        })
    }

    /// Checks if a process name matches this pattern.
    ///
    /// Uses case-insensitive literal substring matching by default, or regex
    /// matching when the pattern uses the explicit regex prefix.
    pub fn matches(&self, process_name: &str) -> bool {
        match &self.strategy {
            PatternStrategy::Literal { needle } => process_name.to_lowercase().contains(needle),
            PatternStrategy::Regex(regex) => regex.is_match(process_name),
        }
    }

    /// Returns the original pattern string.
    pub fn pattern(&self) -> &str {
        &self.original
    }
}

impl ProcessFilter {
    /// Creates an empty filter that allows all processes.
    pub fn new() -> Self {
        Self {
            global_whitelist: Arc::new(Vec::new()),
            global_blacklist: Arc::new(Vec::new()),
            per_listener_whitelist: Vec::new(),
            per_listener_blacklist: Vec::new(),
        }
    }

    /// Builds a process filter with pre-compiled patterns.
    ///
    /// Literal patterns are matched case-insensitively. Regex matching requires
    /// the `re:` or `regex:` prefix and invalid regex patterns are rejected.
    ///
    /// # Arguments
    ///
    /// * `global_whitelist` - Patterns that must match (shared across all listeners)
    /// * `global_blacklist` - Patterns that must not match (shared across all listeners)
    /// * `listener_whitelist` - Patterns specific to this listener
    /// * `listener_blacklist` - Patterns specific to this listener
    pub fn build(
        global_whitelist: Vec<String>,
        global_blacklist: Vec<String>,
        listener_whitelist: Vec<String>,
        listener_blacklist: Vec<String>,
    ) -> crate::Result<Self> {
        let global_wl: Vec<PatternMatcher> = global_whitelist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        let global_bl: Vec<PatternMatcher> = global_blacklist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        let listener_wl: Vec<PatternMatcher> = listener_whitelist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        let listener_bl: Vec<PatternMatcher> = listener_blacklist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        Ok(Self {
            global_whitelist: Arc::new(global_wl),
            global_blacklist: Arc::new(global_bl),
            per_listener_whitelist: listener_wl,
            per_listener_blacklist: listener_bl,
        })
    }

    /// Checks if a process is allowed based on filter rules.
    ///
    /// Returns `true` if the process passes all filter checks.
    /// See struct documentation for evaluation order.
    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        if !self.global_whitelist.is_empty() {
            let matched = self
                .global_whitelist
                .iter()
                .any(|p| p.matches(process_name));
            if !matched {
                return false;
            }
        }

        if !self.global_blacklist.is_empty() {
            let matched = self
                .global_blacklist
                .iter()
                .any(|p| p.matches(process_name));
            if matched {
                return false;
            }
        }

        if !self.per_listener_whitelist.is_empty()
            && !self
                .per_listener_whitelist
                .iter()
                .any(|p| p.matches(process_name))
        {
            return false;
        }

        if !self.per_listener_blacklist.is_empty() {
            return !self
                .per_listener_blacklist
                .iter()
                .any(|p| p.matches(process_name));
        }

        true
    }

    /// Returns the global whitelist pattern strings (for debugging).
    pub fn global_whitelist_patterns(&self) -> Vec<&str> {
        self.global_whitelist.iter().map(|p| p.pattern()).collect()
    }

    /// Returns the global blacklist pattern strings (for debugging).
    pub fn global_blacklist_patterns(&self) -> Vec<&str> {
        self.global_blacklist.iter().map(|p| p.pattern()).collect()
    }
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache for pre-compiled global process filters.
///
/// Used to share compiled patterns across all listeners, avoiding
/// redundant compilation of the same global patterns.
pub struct GlobalProcessFilters {
    whitelist: Arc<Vec<PatternMatcher>>,
    blacklist: Arc<Vec<PatternMatcher>>,
}

impl GlobalProcessFilters {
    /// Creates a new global filter cache with pre-compiled patterns.
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>) -> crate::Result<Self> {
        let wl: Vec<PatternMatcher> = whitelist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        let bl: Vec<PatternMatcher> = blacklist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect::<crate::Result<Vec<_>>>()?;

        Ok(Self {
            whitelist: Arc::new(wl),
            blacklist: Arc::new(bl),
        })
    }

    /// Returns a reference to the compiled whitelist patterns.
    pub fn whitelist(&self) -> &Arc<Vec<PatternMatcher>> {
        &self.whitelist
    }

    /// Returns a reference to the compiled blacklist patterns.
    pub fn blacklist(&self) -> &Arc<Vec<PatternMatcher>> {
        &self.blacklist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matcher_explicit_regex() {
        let pm = PatternMatcher::new("re:^chrome.*").expect("regex should compile");
        assert!(pm.matches("chrome.exe"));
        assert!(pm.matches("chrome_helper"));
        assert!(!pm.matches("firefox.exe"));
    }

    #[test]
    fn test_pattern_matcher_literal_substring() {
        let pm = PatternMatcher::new("Chrome").expect("literal pattern should compile");
        assert!(pm.matches("chrome.exe"));
        assert!(pm.matches("GoogleChromeHelper"));
        assert!(!pm.matches("firefox.exe"));
    }

    #[test]
    fn test_literal_pattern_does_not_treat_dot_as_regex_wildcard() {
        let pm = PatternMatcher::new("svchost.exe").expect("literal pattern should compile");
        assert!(pm.matches("svchost.exe"));
        assert!(!pm.matches("svchostXexe"));
    }

    #[test]
    fn test_invalid_explicit_regex_rejects_pattern() {
        let err = PatternMatcher::new("re:[invalid").expect_err("invalid regex should fail");
        assert!(
            err.to_string().contains("Invalid process filter regex"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_empty_patterns_reject_input() {
        assert!(PatternMatcher::new("").is_err());
        assert!(PatternMatcher::new("re:").is_err());
        assert!(PatternMatcher::new("regex:").is_err());
    }

    #[test]
    fn test_whitespace_only_patterns_reject_input() {
        assert!(PatternMatcher::new("   ").is_err());
        assert!(PatternMatcher::new("\t\n").is_err());
        assert!(PatternMatcher::new("\u{00a0}").is_err());
    }

    #[test]
    fn test_literal_patterns_preserve_meaningful_spaces() {
        let pm = PatternMatcher::new("Google Chrome").expect("pattern should compile");

        assert!(pm.matches("google chrome.exe"));
        assert!(!pm.matches("googlechrome.exe"));
    }

    #[test]
    fn test_process_filter_whitelist() {
        let filter = ProcessFilter::build(vec!["re:chrome.*".to_string()], vec![], vec![], vec![])
            .expect("whitelist should compile");

        assert!(filter.is_process_allowed("chrome.exe"));
        assert!(filter.is_process_allowed("chrome_helper"));
        assert!(!filter.is_process_allowed("firefox.exe"));
    }

    #[test]
    fn test_process_filter_blacklist() {
        let filter = ProcessFilter::build(vec![], vec!["re:malware.*".to_string()], vec![], vec![])
            .expect("blacklist should compile");

        assert!(!filter.is_process_allowed("malware.exe"));
        assert!(!filter.is_process_allowed("malware_agent"));
        assert!(filter.is_process_allowed("chrome.exe"));
    }

    #[test]
    fn test_empty_filter_entries_reject_input() {
        assert!(ProcessFilter::build(vec!["".to_string()], vec![], vec![], Vec::new()).is_err());
        assert!(ProcessFilter::build(vec![], vec!["re:".to_string()], vec![], Vec::new()).is_err());
    }

    #[test]
    fn test_whitespace_only_filter_entries_reject_input() {
        assert!(
            ProcessFilter::build(vec![" \t ".to_string()], vec![], vec![], Vec::new()).is_err()
        );
        assert!(
            ProcessFilter::build(vec![], vec![" \n ".to_string()], vec![], Vec::new()).is_err()
        );
    }

    #[test]
    fn test_process_filter_trims_ascii_edges_before_compiling() {
        let filter =
            ProcessFilter::build(vec!["  re:chrome.* \t".to_string()], vec![], vec![], vec![])
                .expect("regex should compile");

        assert!(filter.is_process_allowed("chrome.exe"));
        assert!(filter.is_process_allowed("chrome_helper"));
        assert!(!filter.is_process_allowed("firefox.exe"));
        assert_eq!(filter.global_whitelist_patterns(), vec!["re:chrome.*"]);
    }

    #[test]
    fn test_process_filter_literal_matching_is_unicode_case_insensitive() {
        let filter = ProcessFilter::build(vec!["müller".to_string()], vec![], vec![], vec![])
            .expect("pattern should compile");

        assert!(filter.is_process_allowed("MÜLLER.exe"));
        assert!(!filter.is_process_allowed("MULLER.exe"));
    }

    #[test]
    fn test_process_filter_combined() {
        let filter = ProcessFilter::build(
            vec!["re:^[a-z]+\\.exe$".to_string()], // whitelist: simple names
            vec!["re:bad.*".to_string()],          // global blacklist
            vec!["re:chrome.*".to_string()],       // listener whitelist
            vec![],
        )
        .expect("patterns should compile");

        assert!(!filter.is_process_allowed("firefox.exe"));
        assert!(!filter.is_process_allowed("bad.exe"));
        assert!(filter.is_process_allowed("chrome.exe"));
    }
}
