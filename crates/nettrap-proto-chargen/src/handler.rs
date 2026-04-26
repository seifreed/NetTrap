/// Character Generator protocol handler (TCP+UDP/19, RFC 864)
///
/// Returns cycling lines of printable ASCII characters (columns 0-71).
pub struct ChargenHandler {
    offset: usize,
}

/// The 95 printable ASCII characters (0x20..=0x7E).
const PRINTABLE: &[u8; 95] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
const MAX_CHARGEN_LINES: usize = 64;

impl ChargenHandler {
    pub fn new() -> Self {
        Self { offset: 0 }
    }

    /// Generate `num_lines` of chargen output (72 chars per line + CRLF).
    /// Each line starts one character further into the printable set.
    pub fn handle(&mut self, num_lines: usize) -> Vec<u8> {
        let num_lines = num_lines.min(MAX_CHARGEN_LINES);
        tracing::info!("Chargen: generating {} lines", num_lines);
        let mut buf = Vec::with_capacity(num_lines.saturating_mul(74));
        for _ in 0..num_lines {
            for col in 0..72 {
                buf.push(PRINTABLE[(self.offset + col) % PRINTABLE.len()]);
            }
            buf.extend_from_slice(b"\r\n");
            self.offset = (self.offset + 1) % PRINTABLE.len();
        }
        buf
    }

    /// Generate a single UDP response (max 512 bytes per RFC).
    pub fn handle_udp(&mut self) -> Vec<u8> {
        self.handle(6) // 6 lines * ~74 bytes = ~444 bytes < 512
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
        let mut handler = ChargenHandler::new();

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
}
