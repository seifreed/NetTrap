pub fn not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\nNot Found"
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::not_found_response;

    #[test]
    fn not_found_response_serializes_expected_body() {
        let response = not_found_response();
        let Ok(text) = std::str::from_utf8(&response) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("Content-Type: text/html\r\n"));
        assert!(text.contains("Content-Length: 9\r\n"));
        assert!(text.ends_with("Not Found"));
    }
}
