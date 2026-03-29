use rand::Rng;

/// Quote of the Day protocol handler (TCP+UDP/17, RFC 865)
///
/// Returns a random quote from a built-in list on each connection.
pub struct QuotdHandler {
    quotes: Vec<&'static str>,
}

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
        let idx = rand::rng().random_range(0..self.quotes.len());
        let quote = self.quotes[idx];
        tracing::info!("QOTD: {}", quote);
        format!("{}\r\n", quote)
    }
}

impl Default for QuotdHandler {
    fn default() -> Self {
        Self::new()
    }
}
