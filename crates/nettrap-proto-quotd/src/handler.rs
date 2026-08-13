use rand::Rng;

/// Quote of the Day protocol handler (TCP+UDP/17, RFC 865)
///
/// Returns a random quote from a built-in list on each connection.
pub struct QuotdHandler {
    quotes: Vec<&'static str>,
}

const FALLBACK_QUOTE: &str = "No quote available.";

const DEFAULT_QUOTES: &[&str] = &[
    "The only way to do great work is to love what you do. - Steve Jobs",
    "In the middle of difficulty lies opportunity. - Albert Einstein",
    "Knowledge is power. - Francis Bacon",
    "The best time to plant a tree was 20 years ago. The second best time is now.",
    "It does not matter how slowly you go as long as you do not stop. - Confucius",
    "Everything should be made as simple as possible, but no simpler. - Einstein",
    "The unexamined life is not worth living. - Socrates",
    "To be or not to be, that is the question. - Shakespeare",
    "I think, therefore I am. - Descartes",
    "That which does not kill us makes us stronger. - Nietzsche",
];

impl QuotdHandler {
    pub fn new() -> Self {
        Self {
            quotes: DEFAULT_QUOTES.to_vec(),
        }
    }

    /// Returns a random quote followed by CRLF.
    pub fn handle(&self) -> String {
        let quote = if self.quotes.is_empty() {
            FALLBACK_QUOTE
        } else {
            let idx = rand::rng().random_range(0..self.quotes.len());
            self.quotes.get(idx).copied().unwrap_or(FALLBACK_QUOTE)
        };
        tracing::info!("QOTD: {}", quote);
        format!("{}\r\n", quote)
    }
}

impl Default for QuotdHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_random_quote_with_trailing_crlf() {
        let handler = QuotdHandler::new();
        let response = handler.handle();

        assert!(response.ends_with("\r\n"));
        assert!(!response.trim_end().is_empty());
    }

    #[test]
    fn returns_fallback_when_no_quotes_are_configured() {
        let handler = QuotdHandler { quotes: Vec::new() };

        assert_eq!(handler.handle(), format!("{FALLBACK_QUOTE}\r\n"));
    }
}
