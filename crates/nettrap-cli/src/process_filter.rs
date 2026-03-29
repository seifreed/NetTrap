use std::sync::Arc;

/// Process filter supporting pre-compiled regex and substring patterns.
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
/// Patterns are pre-compiled at creation time to prevent ReDoS attacks from
/// user-supplied patterns.
#[derive(Clone)]
pub struct ProcessFilter {
    global_whitelist: Arc<Vec<PatternMatcher>>,
    global_blacklist: Arc<Vec<PatternMatcher>>,
    per_listener_whitelist: Vec<PatternMatcher>,
    per_listener_blacklist: Vec<PatternMatcher>,
}

/// Compiled pattern supporting regex or substring matching.
///
/// If the pattern is a valid regex, it will be compiled and used for matching.
/// If the pattern is not a valid regex, it falls back to case-insensitive
/// substring matching.
#[derive(Clone)]
pub struct PatternMatcher {
    original: String,
    compiled: Option<regex::Regex>,
}

impl PatternMatcher {
    /// Creates a new pattern matcher from a string pattern.
    ///
    /// If the pattern is a valid regex, it will be compiled. Otherwise,
    /// it will use case-insensitive substring matching.
    pub fn new(pattern: &str) -> Self {
        let compiled = regex::Regex::new(pattern).ok();
        Self {
            original: pattern.to_string(),
            compiled,
        }
    }

    /// Checks if a process name matches this pattern.
    ///
    /// Uses regex matching if pattern compiled successfully, otherwise
    /// falls back to case-insensitive substring matching.
    pub fn matches(&self, process_name: &str) -> bool {
        if let Some(ref re) = self.compiled {
            re.is_match(process_name)
        } else {
            process_name
                .to_lowercase()
                .contains(&self.original.to_lowercase())
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
    /// All patterns are compiled at creation time to prevent ReDoS attacks.
    /// Invalid regex patterns fall back to substring matching.
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
    ) -> Self {
        let global_wl: Vec<PatternMatcher> = global_whitelist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect();

        let global_bl: Vec<PatternMatcher> = global_blacklist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect();

        let listener_wl: Vec<PatternMatcher> = listener_whitelist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect();

        let listener_bl: Vec<PatternMatcher> = listener_blacklist
            .iter()
            .map(|p| PatternMatcher::new(p))
            .collect();

        Self {
            global_whitelist: Arc::new(global_wl),
            global_blacklist: Arc::new(global_bl),
            per_listener_whitelist: listener_wl,
            per_listener_blacklist: listener_bl,
        }
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

        if !self.per_listener_whitelist.is_empty() {
            return self
                .per_listener_whitelist
                .iter()
                .any(|p| p.matches(process_name));
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
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>) -> Self {
        let wl: Vec<PatternMatcher> = whitelist.iter().map(|p| PatternMatcher::new(p)).collect();

        let bl: Vec<PatternMatcher> = blacklist.iter().map(|p| PatternMatcher::new(p)).collect();

        Self {
            whitelist: Arc::new(wl),
            blacklist: Arc::new(bl),
        }
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
    fn test_pattern_matcher_regex() {
        let pm = PatternMatcher::new("^chrome.*");
        assert!(pm.matches("chrome.exe"));
        assert!(pm.matches("chrome_helper"));
        assert!(!pm.matches("firefox.exe"));
    }

    #[test]
    fn test_pattern_matcher_substring() {
        // Invalid regex falls back to substring matching
        let pm = PatternMatcher::new("[invalid");
        assert!(pm.matches("foo[invalidbar"));
        assert!(!pm.matches("foobar"));
    }

    #[test]
    fn test_process_filter_whitelist() {
        let filter = ProcessFilter::build(vec!["chrome.*".to_string()], vec![], vec![], vec![]);

        assert!(filter.is_process_allowed("chrome.exe"));
        assert!(filter.is_process_allowed("chrome_helper"));
        assert!(!filter.is_process_allowed("firefox.exe"));
    }

    #[test]
    fn test_process_filter_blacklist() {
        let filter = ProcessFilter::build(vec![], vec!["malware.*".to_string()], vec![], vec![]);

        assert!(!filter.is_process_allowed("malware.exe"));
        assert!(!filter.is_process_allowed("malware_agent"));
        assert!(filter.is_process_allowed("chrome.exe"));
    }

    #[test]
    fn test_process_filter_combined() {
        let filter = ProcessFilter::build(
            vec!["^[a-z]+\\.exe$".to_string()], // whitelist: simple names
            vec!["bad.*".to_string()],          // global blacklist
            vec!["chrome.*".to_string()],       // listener whitelist
            vec![],
        );

        // Whitelist blocks non-matching
        assert!(!filter.is_process_allowed("firefox.exe"));
        // But blacklist still applies
        assert!(!filter.is_process_allowed("bad.exe"));
        // Both pass
        assert!(filter.is_process_allowed("chrome.exe"));
    }
}
