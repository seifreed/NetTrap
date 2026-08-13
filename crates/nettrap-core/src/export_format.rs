use std::fmt;

/// Supported export file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Jsonl,
    Sarif,
    Toon,
    Csv,
}

impl ExportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Sarif => "sarif.json",
            Self::Toon => "toon",
            Self::Csv => "csv",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFormatParseError {
    value: String,
}

impl ExportFormatParseError {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl fmt::Display for ExportFormatParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported output format '{}'; expected one of: json, jsonl, ndjson, sarif, toon, csv",
            self.value
        )
    }
}

impl std::error::Error for ExportFormatParseError {}

impl std::str::FromStr for ExportFormat {
    type Err = ExportFormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim_matches([' ', '\t']);
        if trimmed.is_empty()
            || trimmed
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return Err(ExportFormatParseError::new(s));
        }

        let format = match trimmed.to_lowercase().as_str() {
            "json" => Self::Json,
            "jsonl" | "ndjson" => Self::Jsonl,
            "sarif" => Self::Sarif,
            "toon" => Self::Toon,
            "csv" => Self::Csv,
            _ => return Err(ExportFormatParseError::new(s)),
        };
        Ok(format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_format_rejects_unknown_values() {
        assert_eq!("json".parse::<ExportFormat>().unwrap(), ExportFormat::Json);
        assert_eq!(
            "ndjson".parse::<ExportFormat>().unwrap(),
            ExportFormat::Jsonl
        );

        let err = "xml".parse::<ExportFormat>().unwrap_err();
        assert!(err.to_string().contains("unsupported output format 'xml'"));
    }

    #[test]
    fn export_format_rejects_unicode_whitespace_padding() {
        assert!("json\u{00a0}".parse::<ExportFormat>().is_err());
        assert!("\u{2003}csv".parse::<ExportFormat>().is_err());
    }
}
