//! WinDivert DLL discovery and loading.
//!
//! This module handles finding and loading the WinDivert DLL at runtime.

use std::path::Path;

pub(crate) fn is_trusted_dll_candidate(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(windows)]
pub mod windivert_dll {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    use crate::dll::is_trusted_dll_candidate;

    static WINDIVERT_PATH: OnceLock<PathBuf> = OnceLock::new();

    /// Find WinDivert DLL in common locations
    pub fn find_windivert_dll() -> Option<PathBuf> {
        Some(
            WINDIVERT_PATH
                .get_or_init(|| {
                    // Try common locations in order
                    let candidates = get_dll_search_paths();

                    for path in candidates {
                        let dll_path = path.join(get_dll_name());
                        if is_trusted_dll_candidate(&dll_path) {
                            tracing::debug!("Found WinDivert DLL at: {:?}", dll_path);
                            return dll_path;
                        }
                    }

                    tracing::warn!(
                        "WinDivert DLL not found in search paths, will try loading from PATH"
                    );
                    PathBuf::from(get_dll_name())
                })
                .clone(),
        )
    }

    fn get_dll_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Ok(cwd) = std::env::current_dir() {
            paths.push(cwd.clone());
            paths.push(cwd.join("windivert"));
        }

        if let Ok(exe_path) = std::env::current_exe()
            && let Some(parent) = exe_path.parent()
        {
            let parent = parent.to_path_buf();
            paths.push(parent.clone());
            paths.push(parent.join("windivert"));
            if let Some(target_dir) = parent.parent() {
                paths.push(target_dir.join("windivert"));
            }
        }

        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let lib_path = PathBuf::from(manifest_dir)
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("windivert"))
                .unwrap_or_default();
            paths.push(lib_path);
        }

        paths.push(PathBuf::from("C:\\Windows\\System32"));

        paths
    }

    fn get_dll_name() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "WinDivert.dll"
        } else {
            "WinDivert32.dll"
        }
    }

    pub fn get_driver_name() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "WinDivert64.sys"
        } else {
            "WinDivert32.sys"
        }
    }
}

#[cfg(not(windows))]
pub mod windivert_dll {
    use std::path::PathBuf;

    pub fn find_windivert_dll() -> Option<PathBuf> {
        None
    }

    pub fn get_driver_name() -> &'static str {
        ""
    }
}
