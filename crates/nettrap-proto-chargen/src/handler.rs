use std::sync::{Arc, Mutex};

use rand::Rng;

/// Character Generator protocol handler (TCP+UDP/19, RFC 864)
///
/// Returns cycling lines of printable ASCII characters (columns 0-71).
#[derive(Clone)]
pub struct ChargenHandler {
    offset: Arc<Mutex<usize>>,
}

/// The 95 printable ASCII characters (0x20..=0x7E).
const PRINTABLE: &[u8; 95] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
const MAX_CHARGEN_LINES: usize = 64;
const MAX_CHARGEN_UDP_BYTES: usize = 512;

impl ChargenHandler {
    pub fn new() -> Self {
        Self {
            offset: Arc::new(Mutex::new(0)),
        }
    }

    /// Generate `num_lines` of chargen output (72 chars per line + CRLF).
    /// Each line starts one character further into the printable set.
    pub fn handle(&self, num_lines: usize) -> Vec<u8> {
        let num_lines = num_lines.min(MAX_CHARGEN_LINES);
        tracing::info!("Chargen: generating {} lines", num_lines);
        let mut buf = Vec::with_capacity(num_lines.saturating_mul(74));
        let printable_len = PRINTABLE.len();
        let mut offset = self
            .offset
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for _ in 0..num_lines {
            buf.extend(Self::render_sequence(*offset % printable_len, 72));
            buf.extend_from_slice(b"\r\n");
            *offset = (*offset + 1) % printable_len;
        }
        buf
    }

    /// Generate a single UDP response with no shared history.
    pub fn handle_udp(&self) -> Vec<u8> {
        let mut rng = rand::rng();
        let len = rng.random_range(0..=MAX_CHARGEN_UDP_BYTES);
        let start_offset = rng.random_range(0..PRINTABLE.len());

        tracing::info!("Chargen: generating {} UDP bytes", len);

        Self::render_sequence(start_offset, len)
    }

    fn render_sequence(start_offset: usize, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        let mut chars = PRINTABLE
            .iter()
            .copied()
            .cycle()
            .skip(start_offset % PRINTABLE.len());
        buf.extend(chars.by_ref().take(len));
        buf
    }
}

impl Default for ChargenHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_caps_requested_lines_to_bounded_response() {
        let handler = ChargenHandler::new();

        let response = handler.handle(usize::MAX);

        assert_eq!(response.len(), MAX_CHARGEN_LINES * 74);
        assert_eq!(
            response
                .windows(2)
                .filter(|window| *window == b"\r\n")
                .count(),
            64
        );
    }

    #[test]
    fn handle_advances_offset_across_calls() {
        let handler = ChargenHandler::new();

        let first = handler.handle(1);
        let second = handler.handle(1);

        assert_ne!(first, second);
        assert_eq!(&first[..72], &PRINTABLE[..72]);
        assert_eq!(&second[..72], &PRINTABLE[1..73]);
    }

    #[test]
    fn handle_udp_does_not_advance_tcp_offset() {
        let handler = ChargenHandler::new();

        let response = handler.handle_udp();
        let tcp = handler.handle(1);

        assert!(response.len() <= MAX_CHARGEN_UDP_BYTES);
        assert_eq!(&tcp[..72], &PRINTABLE[..72]);
    }
}
