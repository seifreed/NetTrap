use std::io::Write;
use std::path::Path;

use nettrap_fsutil::create_regular_file;

use super::parsing::read_engine_config_file;
use super::{CONFIG_VERSION, EngineConfig};

impl EngineConfig {
    pub fn from_file(path: &Path) -> crate::Result<Self> {
        let mut config = Self::from_file_declarative(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file_api(path: &Path) -> crate::Result<Self> {
        let mut config = Self::from_file_declarative(path)?;
        config.prepare_api_defaults()?;
        Ok(config)
    }

    pub fn from_file_declarative(path: &Path) -> crate::Result<Self> {
        let content = read_engine_config_file(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Migrate a configuration file to the current schema and validate it.
    ///
    /// Older versions are upgraded in memory before normal validation. Future
    /// versions are rejected so unknown fields cannot be silently discarded.
    pub fn migrate_file(input: &Path, output: &Path) -> crate::Result<()> {
        let content = read_engine_config_file(input)?;
        let mut document: toml::Value = toml::from_str(&content)
            .map_err(|error| crate::Error::Config(format!("invalid TOML: {error}")))?;
        let version = document
            .get("config_version")
            .and_then(toml::Value::as_integer)
            .unwrap_or(0);

        if !(0..=i64::from(u32::MAX)).contains(&version) {
            return Err(crate::Error::Config(format!(
                "unsupported config_version {}; expected at most {}",
                version, CONFIG_VERSION
            )));
        }
        if version > i64::from(CONFIG_VERSION) {
            return Err(crate::Error::Config(format!(
                "config_version {} is newer than supported version {}",
                version, CONFIG_VERSION
            )));
        }

        let table = document.as_table_mut().ok_or_else(|| {
            crate::Error::Config("configuration root must be a TOML table".to_string())
        })?;
        table.insert(
            "config_version".to_string(),
            toml::Value::Integer(i64::from(CONFIG_VERSION)),
        );

        let mut config: Self = document
            .try_into()
            .map_err(|error| crate::Error::Config(format!("invalid configuration: {error}")))?;
        config.validate()?;
        config.to_file(output)
    }

    pub fn to_file(&self, path: &Path) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        let mut file = create_regular_file(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}
