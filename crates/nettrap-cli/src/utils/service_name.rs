use rand::Rng;

pub fn resolve_service_name(input: &str) -> String {
    if input == "!hostname" || input == "!gethostname" {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "nettrap.local".to_string())
    } else if input == "!random" {
        let mut rng = rand::rng();
        let len = rng.random_range(5..=12);
        let name: String = (0..len)
            .map(|_| rng.random_range(b'a'..=b'z') as char)
            .collect();
        format!("{}.local", name)
    } else if input.contains('.') && !input.starts_with('.') {
        input.split_whitespace().next().unwrap_or(input).to_string()
    } else {
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_hostname() {
        let result = resolve_service_name("!hostname");
        assert!(!result.is_empty());
        assert_ne!(result, "nettrap.local");
    }

    #[test]
    fn test_resolve_random() {
        let result = resolve_service_name("!random");
        assert!(result.ends_with(".local"));
    }

    #[test]
    fn test_resolve_domain() {
        assert_eq!(resolve_service_name("example.com"), "example.com");
        assert_eq!(resolve_service_name("mail.example.com"), "mail.example.com");
    }

    #[test]
    fn test_resolve_domain_with_spaces() {
        assert_eq!(resolve_service_name("example.com extra"), "example.com");
    }

    #[test]
    fn test_resolve_plain() {
        assert_eq!(resolve_service_name("localhost"), "localhost");
        assert_eq!(resolve_service_name("myserver"), "myserver");
    }
}
