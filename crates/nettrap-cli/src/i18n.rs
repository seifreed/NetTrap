//! Internationalization for NetTrap reports.

mod translations;

use translations::TRANSLATIONS;

/// Get translation for a key in the specified language.
///
/// Returns an error when the language or key is missing instead of silently
/// falling back to English or the key itself.
pub fn t<'a>(key: &'a str, lang: &str) -> crate::Result<&'a str> {
    let Some(map) = TRANSLATIONS.get(lang) else {
        return Err(crate::Error::Config(format!(
            "unsupported report language '{}'",
            lang
        )));
    };

    map.get(key).copied().ok_or_else(|| {
        crate::Error::Config(format!(
            "translation key '{}' is missing for language '{}'",
            key, lang
        ))
    })
}

/// List of supported language codes
pub const SUPPORTED_LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("es", "Español"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("it", "Italiano"),
    ("pt", "Português"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("ro", "Română"),
    ("sv", "Svenska"),
    ("da", "Dansk"),
    ("fi", "Suomi"),
    ("el", "Ελληνικά"),
    ("hu", "Magyar"),
    ("cs", "Čeština"),
    ("sk", "Slovenčina"),
    ("sl", "Slovenščina"),
    ("hr", "Hrvatski"),
    ("bg", "Български"),
    ("et", "Eesti"),
    ("lv", "Latviešu"),
    ("lt", "Lietuvių"),
    ("mt", "Malti"),
    ("ga", "Gaeilge"),
    ("eu", "Euskara"),
    ("ca", "Català"),
    ("zh", "中文"),
    ("hi", "हिन्दी"),
    ("ru", "Русский"),
    ("bn", "বাংলা"),
    ("ur", "اردو"),
    ("ar", "العربية"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_fallback() {
        assert_eq!(
            t("total_events", "en").expect("translation should exist"),
            "Total Events"
        );
    }

    #[test]
    fn test_spanish_translation() {
        assert_eq!(
            t("total_events", "es").expect("translation should exist"),
            "Total de Eventos"
        );
    }

    #[test]
    fn test_unknown_language_returns_error() {
        let err = t("total_events", "xx").expect_err("unknown language should fail");
        assert!(err.to_string().contains("unsupported report language"));
    }

    #[test]
    fn test_unknown_key_returns_error() {
        let err = t("nonexistent_key", "en").expect_err("unknown key should fail");
        assert!(err.to_string().contains("missing for language"));
    }

    #[test]
    fn test_all_supported_languages_have_report_title() {
        for (code, _name) in SUPPORTED_LANGUAGES {
            let title = t("report_title", code).expect("supported languages must be complete");
            assert!(
                title.contains("NetTrap"),
                "Language {} missing report_title",
                code
            );
        }
    }

    #[test]
    fn test_supported_languages_count() {
        assert!(
            SUPPORTED_LANGUAGES.len() >= 32,
            "Expected 32+ languages, got {}",
            SUPPORTED_LANGUAGES.len()
        );
    }

    #[test]
    fn test_all_supported_languages_are_complete() {
        let en = super::translations::TRANSLATIONS
            .get("en")
            .expect("English translations must exist");
        for (code, name) in SUPPORTED_LANGUAGES {
            let map = super::translations::TRANSLATIONS
                .get(*code)
                .unwrap_or_else(|| {
                    panic!("language {code} ({name}) missing from translation table")
                });
            for key in en.keys() {
                assert!(
                    map.contains_key(key),
                    "language {code} ({name}) is missing translation key '{key}'"
                );
            }
        }
    }
}
