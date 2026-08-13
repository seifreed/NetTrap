/// Format data as hex dump (16 bytes per line) for logging
pub fn hexdump(data: &[u8], max_bytes: usize) -> String {
    if max_bytes == 0 && !data.is_empty() {
        return format!("... ({} bytes, hexdump disabled)\n", data.len());
    }
    let len = data.len().min(max_bytes);
    let mut output = String::new();

    for offset in (0..len).step_by(16) {
        let end = (offset + 16).min(len);
        let chunk = &data[offset..end];

        output.push_str(&format!("{:08x}  ", offset));

        for (i, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if i == 7 {
                output.push(' ');
            }
        }

        let padding = 16 - chunk.len();
        for i in 0..padding {
            output.push_str("   ");
            if chunk.len() + i == 7 {
                output.push(' ');
            }
        }

        output.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    if data.len() > max_bytes {
        output.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump_basic() {
        let data = b"Hello, World!";
        let result = hexdump(data, 256);
        assert!(result.contains("48 65 6c 6c 6f"));
        assert!(result.contains("|Hello, World!|"));
    }
}
