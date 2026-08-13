use std::io::Write;
use std::path::Path;

use nettrap_fsutil::create_regular_file;

use super::EngineConfig;
use super::parsing::read_engine_config_file;

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

    pub fn to_file(&self, path: &Path) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        let mut file = create_regular_file(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}
