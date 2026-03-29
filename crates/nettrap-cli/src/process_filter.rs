use std::sync::Arc;

/// Pre-compiled process filter for whitelist/blacklist matching
#[derive(Clone)]
pub struct ProcessFilter {
    global_whitelist: Arc<Vec<PatternMatcher>>,
    global_blacklist: Arc<Vec<PatternMatcher>>,
    per_listener_whitelist: Vec<PatternMatcher>,
    per_listener_blacklist: Vec<PatternMatcher>,
}

/// Compiled pattern that can match via regex or substring
#[derive(Clone)]
pub struct PatternMatcher {
    original: String,
    compiled: Option<regex::Regex>,
}

impl PatternMatcher {
    pub fn new(pattern: &str) -> Self {
        let compiled = regex::Regex::new(pattern).ok();
        Self {
            original: pattern.to_string(),
            compiled,
        }
    }

    /// Check if process name matches this pattern
    pub fn matches(&self, process_name: &str) -> bool {
        if let Some(ref re) = self.compiled {
            re.is_match(process_name)
        } else {
            // Fallback to case-insensitive substring match
            process_name
                .to_lowercase()
                .contains(&self.original.to_lowercase())
        }
    }

    /// Get the original pattern string
    pub fn pattern(&self) -> &str {
        &self.original
    }
}

impl ProcessFilter {
    pub fn new() -> Self {
        Self {
            global_whitelist: Arc::new(Vec::new()),
            global_blacklist: Arc::new(Vec::new()),
            per_listener_whitelist: Vec::new(),
            per_listener_blacklist: Vec::new(),
        }
    }

    /// Create a process filter with pre-compiled patterns
    pub fn build(
        global_whitelist: Vec<String>,
        global_blacklist: Vec<String>,
        listener_whitelist: Vec<String>,
        listener_blacklist: Vec<String>,
    ) -> Self {
        // Pre-compile all patterns at creation time
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

    /// Check if a process is allowed based on the filters
    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        // Check global filters first
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

        // Check per-listener filters
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

    /// Get global whitelist patterns (for debugging)
    pub fn global_whitelist_patterns(&self) -> Vec<&str> {
        self.global_whitelist.iter().map(|p| p.pattern()).collect()
    }

    /// Get global blacklist patterns (for debugging)
    pub fn global_blacklist_patterns(&self) -> Vec<&str> {
        self.global_blacklist.iter().map(|p| p.pattern()).collect()
    }
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Global cache for pre-compiled patterns to avoid recompilation across listeners
pub struct GlobalProcessFilters {
    whitelist: Arc<Vec<PatternMatcher>>,
    blacklist: Arc<Vec<PatternMatcher>>,
}

impl GlobalProcessFilters {
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>) -> Self {
        let wl: Vec<PatternMatcher> = whitelist.iter().map(|p| PatternMatcher::new(p)).collect();

        let bl: Vec<PatternMatcher> = blacklist.iter().map(|p| PatternMatcher::new(p)).collect();

        Self {
            whitelist: Arc::new(wl),
            blacklist: Arc::new(bl),
        }
    }

    pub fn whitelist(&self) -> &Arc<Vec<PatternMatcher>> {
        &self.whitelist
    }

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
