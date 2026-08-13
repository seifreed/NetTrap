use std::path::Path;

use nettrap_fsutil::{ensure_no_symlink_ancestors, strip_current_dir_components};

pub(super) fn validate_output_file_path(path: &Path) -> crate::Result<()> {
    let normalized_path = strip_current_dir_components(path);
    let path = normalized_path.as_path();

    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(crate::Error::Config(format!(
            "output path {} is a symlink, expected a writable file",
            path.display()
        )));
    }

    if path.is_dir() {
        return Err(crate::Error::Config(format!(
            "output path {} is a directory, expected a writable file",
            path.display()
        )));
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_no_symlink_ancestors(parent).map_err(|err| {
            crate::Error::Config(format!(
                "failed to validate writable output path {}: {}",
                path.display(),
                err
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(|err| {
            crate::Error::Config(format!(
                "failed to create output directory {}: {}",
                parent.display(),
                err
            ))
        })?;
    }

    Ok(())
}
