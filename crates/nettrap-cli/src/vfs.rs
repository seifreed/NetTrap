//! Virtual Filesystem (VFS) — provides a fake filesystem for honeypot services
//! (FTP, TFTP, SMB, etc.) without exposing real host files.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Component, Path};

use nettrap_fsutil::open_regular_file_beneath_root;

const MAX_SEED_DEPTH: usize = 20;
const MAX_SEED_ENTRIES: usize = 4096;
const MAX_SEED_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_SEED_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// A single entry in the virtual filesystem
#[derive(Debug, Clone)]
pub enum VfsEntry {
    File { content: Vec<u8>, size: u64 },
    Directory,
}

impl VfsEntry {
    pub fn is_file(&self) -> bool {
        matches!(self, VfsEntry::File { .. })
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, VfsEntry::Directory)
    }

    pub fn size(&self) -> u64 {
        match self {
            VfsEntry::File { size, .. } => *size,
            VfsEntry::Directory => 0,
        }
    }
}

/// Virtual filesystem backed by an in-memory HashMap
pub struct VirtualFilesystem {
    entries: RwLock<HashMap<String, VfsEntry>>,
}

impl VirtualFilesystem {
    /// Create a new VFS. If `root_dir` is Some and exists, seed from it;
    /// otherwise populate with default virtual entries.
    pub fn new(root_dir: Option<&str>) -> Self {
        let vfs = Self {
            entries: RwLock::new(HashMap::new()),
        };

        if let Some(dir) = root_dir {
            let path = Path::new(dir);
            let is_real_dir = path
                .symlink_metadata()
                .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                .unwrap_or(false);
            if is_real_dir {
                vfs.seed_from_dir(path, path);
                return vfs;
            }
        }

        vfs.create_dir_internal("/");
        vfs.create_dir_internal("/pub");
        vfs.create_dir_internal("/pub/docs");
        vfs.create_dir_internal("/home");
        vfs.create_dir_internal("/home/admin");
        vfs.create_dir_internal("/var");
        vfs.create_dir_internal("/var/log");
        vfs.create_dir_internal("/tmp");

        vfs.create_file_internal(
            "/pub/readme.txt",
            b"Welcome to the FTP server.\r\n".to_vec(),
        );
        vfs.create_file_internal("/pub/docs/manual.pdf", Self::fake_pdf());
        vfs.create_file_internal(
            "/home/admin/.bashrc",
            b"# .bashrc\nexport PATH=/usr/local/bin:$PATH\n".to_vec(),
        );
        vfs.create_file_internal(
            "/var/log/syslog",
            default_syslog_content(crate::faketime::fake_now()).into_bytes(),
        );

        vfs
    }

    /// Seed VFS entries from a real directory tree (max depth to prevent symlink cycles)
    fn seed_from_dir(&self, base: &Path, current: &Path) {
        let mut budget = SeedBudget::default();
        self.seed_from_dir_depth(base, current, 0, &mut budget);
    }

    fn seed_from_dir_depth(
        &self,
        base: &Path,
        current: &Path,
        depth: usize,
        budget: &mut SeedBudget,
    ) {
        if budget.entry_limit_reached() {
            tracing::warn!(
                "VFS seed_from_dir: max entry count {} reached at {:?}, stopping",
                MAX_SEED_ENTRIES,
                current
            );
            return;
        }

        if depth > MAX_SEED_DEPTH {
            tracing::warn!(
                "VFS seed_from_dir: max depth {} reached at {:?}, stopping (possible symlink cycle)",
                MAX_SEED_DEPTH,
                current
            );
            return;
        }
        // Skip symlinks to prevent cycle traversal
        if current
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            tracing::debug!("VFS seed_from_dir: skipping symlink {:?}", current);
            return;
        }
        match std::fs::read_dir(current) {
            Ok(entries) => {
                let relative = current.strip_prefix(base).unwrap_or(Path::new(""));
                let vfs_dir = relative_vfs_path(relative);
                let vfs_dir = Self::normalize_path(&vfs_dir);
                if !budget.reserve_dir() {
                    tracing::warn!(
                        "VFS seed_from_dir: max entry count {} reached before {:?}, stopping",
                        MAX_SEED_ENTRIES,
                        current
                    );
                    return;
                }
                self.create_dir_internal(&vfs_dir);

                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            tracing::warn!(
                                "VFS seed_from_dir: failed to read directory entry under {:?}: {}",
                                current,
                                err
                            );
                            continue;
                        }
                    };
                    let path = entry.path();
                    let metadata = match path.symlink_metadata() {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            tracing::warn!(
                                "VFS seed_from_dir: failed to read metadata for {:?}: {}",
                                path,
                                err
                            );
                            continue;
                        }
                    };
                    if metadata.file_type().is_symlink() {
                        tracing::debug!("VFS seed_from_dir: skipping symlink {:?}", path);
                        continue;
                    }
                    if metadata.is_dir() {
                        self.seed_from_dir_depth(base, &path, depth + 1, budget);
                    } else if metadata.is_file() {
                        let rel = path.strip_prefix(base).unwrap_or(&path);
                        let vfs_path = relative_vfs_path(rel);
                        let vfs_path = Self::normalize_path(&vfs_path);
                        match budget.reserve_file(&path, metadata.len()) {
                            SeedDecision::Read => match read_seed_file(base, &path) {
                                Ok(Some(content)) => self.create_file_internal(&vfs_path, content),
                                Ok(None) => {}
                                Err(err) => {
                                    tracing::warn!(
                                        "VFS seed_from_dir: failed to read seed file {:?}: {}",
                                        path,
                                        err
                                    );
                                }
                            },
                            SeedDecision::Skip => {}
                            SeedDecision::Stop => return,
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    "VFS seed_from_dir: failed to read directory {:?}: {}",
                    current,
                    err
                );
            }
        }
    }

    fn normalize_path(path: &str) -> String {
        let mut components = Vec::new();
        let normalized = path.replace('\\', "/");
        for component in normalized.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                _ => components.push(component),
            }
        }
        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    fn path_is_safe(path: &str) -> bool {
        !path
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    }

    fn create_dir_internal(&self, path: &str) {
        if !Self::path_is_safe(path) {
            return;
        }
        let path = Self::normalize_path(path);
        let mut entries = self.entries.write();
        if path != "/" {
            let Some(parent) = Self::parent_path(&path) else {
                return;
            };
            if !matches!(entries.get(&parent), Some(VfsEntry::Directory)) {
                return;
            }
        }
        match entries.get(&path) {
            Some(VfsEntry::File { .. }) => {}
            Some(VfsEntry::Directory) => {}
            None => {
                entries.insert(path, VfsEntry::Directory);
            }
        }
    }

    fn create_file_internal(&self, path: &str, content: Vec<u8>) {
        if !Self::path_is_safe(path) {
            return;
        }
        let path = Self::normalize_path(path);
        let size = content.len() as u64;
        let mut entries = self.entries.write();
        let Some(parent) = Self::parent_path(&path) else {
            return;
        };
        if !matches!(entries.get(&parent), Some(VfsEntry::Directory)) {
            return;
        }
        if matches!(entries.get(&path), Some(VfsEntry::Directory)) {
            return;
        }
        entries.insert(path, VfsEntry::File { content, size });
    }

    fn parent_path(path: &str) -> Option<String> {
        let parent = Path::new(path).parent()?;
        let parent = parent.to_str()?;
        Some(Self::normalize_path(parent))
    }

    /// List entries in a directory. Returns (name, is_dir, size) tuples.
    pub fn list(&self, path: &str) -> Vec<(String, bool, u64)> {
        if !Self::path_is_safe(path) {
            return Vec::new();
        }
        let path = Self::normalize_path(path);
        let entries = self.entries.read();
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{}/", path)
        };

        let mut results = Vec::new();
        for (key, entry) in entries.iter() {
            if key == &path {
                continue; // skip the directory itself
            }
            if key.starts_with(&prefix) {
                let rest = &key[prefix.len()..];
                if !rest.contains('/') && !rest.is_empty() {
                    results.push((rest.to_string(), entry.is_dir(), entry.size()));
                }
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        results
    }

    /// Get a file's content
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        if !Self::path_is_safe(path) {
            return None;
        }
        let path = Self::normalize_path(path);
        let entries = self.entries.read();
        match entries.get(&path) {
            Some(VfsEntry::File { content, .. }) => Some(content.clone()),
            _ => None,
        }
    }

    /// Create a file in the VFS
    pub fn create_file(&self, path: &str, content: Vec<u8>) {
        if !Self::path_is_safe(path) || Self::normalize_path(path) == "/" {
            return;
        }
        self.create_file_internal(path, content);
    }

    /// Create a directory in the VFS
    pub fn create_dir(&self, path: &str) {
        if !Self::path_is_safe(path) {
            return;
        }
        self.create_dir_internal(path);
    }

    /// Delete an entry
    pub fn delete(&self, path: &str) -> bool {
        if !Self::path_is_safe(path) {
            return false;
        }
        let path = Self::normalize_path(path);
        if path == "/" {
            return false;
        }
        let mut entries = self.entries.write();
        if matches!(entries.get(&path), Some(VfsEntry::Directory)) {
            let prefix = format!("{path}/");
            if entries.keys().any(|key| key.starts_with(&prefix)) {
                return false;
            }
        }
        entries.remove(&path).is_some()
    }

    /// Check if an entry exists
    pub fn exists(&self, path: &str) -> bool {
        if !Self::path_is_safe(path) {
            return false;
        }
        let path = Self::normalize_path(path);
        self.entries.read().contains_key(&path)
    }

    /// Rename / move an entry (updates children for directory renames)
    pub fn rename(&self, from: &str, to: &str) -> bool {
        if !Self::path_is_safe(from) || !Self::path_is_safe(to) {
            return false;
        }
        let from = Self::normalize_path(from);
        let to = Self::normalize_path(to);
        if from == "/" {
            return false;
        }
        let mut entries = self.entries.write();
        let Some(entry) = entries.get(&from).cloned() else {
            return false;
        };
        if to != from && entries.contains_key(&to) {
            return false;
        }
        let Some(parent) = Self::parent_path(&to) else {
            return false;
        };
        if !matches!(entries.get(&parent), Some(VfsEntry::Directory)) {
            return false;
        }
        let is_dir = entry.is_dir();
        if is_dir && to.starts_with(&format!("{from}/")) {
            return false;
        }

        if let Some(entry) = entries.remove(&from) {
            entries.insert(to.clone(), entry);
            if is_dir {
                let from_prefix = format!("{}/", from);
                let children: Vec<(String, VfsEntry)> = entries
                    .iter()
                    .filter(|(k, _)| k.starts_with(&from_prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (old_key, child_entry) in children {
                    entries.remove(&old_key);
                    let new_key =
                        Self::normalize_path(&format!("{}/{}", to, &old_key[from_prefix.len()..]));
                    entries.insert(new_key, child_entry);
                }
            }
            true
        } else {
            false
        }
    }

    /// Generate a minimal fake PDF
    fn fake_pdf() -> Vec<u8> {
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
          2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
          3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n\
          xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n\
          0000000052 00000 n \n0000000101 00000 n \n\
          trailer<</Size 4/Root 1 0 R>>\nstartxref\n170\n%%EOF"
            .to_vec()
    }
}

fn default_syslog_content(now: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{} localhost kernel: NetTrap VFS initialized\n",
        now.format("%b %e %H:%M:%S")
    )
}

fn safe_vfs_name(value: &OsStr) -> String {
    if let Some(value) = value.to_str() {
        if value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
        {
            let mut rendered = String::from("unnamed-");
            for ch in value.chars() {
                let _ = write!(&mut rendered, "{:x}-", ch as u32);
            }
            rendered.pop();
            return rendered;
        }
        return value.to_owned();
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let mut rendered = String::from("unnamed-");
        for byte in value.as_bytes() {
            let _ = write!(&mut rendered, "{:02x}", byte);
        }
        rendered
    }

    #[cfg(not(unix))]
    {
        "unnamed".to_string()
    }
}

fn relative_vfs_path(path: &Path) -> String {
    let mut parts = Vec::new();
    for component in path.components() {
        if let Component::Normal(value) = component {
            parts.push(safe_vfs_name(value));
        }
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn read_seed_file(base: &Path, path: &Path) -> io::Result<Option<Vec<u8>>> {
    let relative = path
        .strip_prefix(base)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seed file is outside root"))?;
    let file = open_regular_file_beneath_root(base, relative)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_SEED_FILE_BYTES {
        return Ok(None);
    }

    let mut limited = file.take(MAX_SEED_FILE_BYTES + 1);
    let mut content = Vec::new();
    limited.read_to_end(&mut content)?;
    if content.len() as u64 > MAX_SEED_FILE_BYTES {
        return Ok(None);
    }

    Ok(Some(content))
}

#[derive(Default)]
struct SeedBudget {
    entries: usize,
    total_bytes: u64,
}

impl SeedBudget {
    fn entry_limit_reached(&self) -> bool {
        self.entries >= MAX_SEED_ENTRIES
    }

    fn reserve_dir(&mut self) -> bool {
        if self.entry_limit_reached() {
            return false;
        }
        self.entries += 1;
        true
    }

    fn reserve_file(&mut self, path: &Path, file_bytes: u64) -> SeedDecision {
        if self.entry_limit_reached() {
            return SeedDecision::Stop;
        }
        if file_bytes > MAX_SEED_FILE_BYTES {
            tracing::warn!(
                "VFS seed_from_dir: skipping {:?}; size {} exceeds per-file limit {}",
                path,
                file_bytes,
                MAX_SEED_FILE_BYTES
            );
            return SeedDecision::Skip;
        }

        let Some(next_total) = self.total_bytes.checked_add(file_bytes) else {
            return SeedDecision::Stop;
        };

        if next_total > MAX_SEED_TOTAL_BYTES {
            tracing::warn!(
                "VFS seed_from_dir: max total bytes {} reached before {:?}, stopping",
                MAX_SEED_TOTAL_BYTES,
                path
            );
            return SeedDecision::Stop;
        }

        self.entries += 1;
        self.total_bytes = next_total;
        SeedDecision::Read
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedDecision {
    Read,
    Skip,
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(unix, not(target_os = "macos")))]
    use std::ffi::OsString;
    use std::fs::{self, File};
    #[cfg(unix)]
    use std::io;
    #[cfg(all(unix, not(target_os = "macos")))]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    fn test_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("nettrap-vfs-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn seeding_skips_files_over_per_file_limit() {
        let root = test_root("oversized");
        let oversized = root.join("large.bin");
        let file = File::create(&oversized).expect("create sparse test file");
        file.set_len(MAX_SEED_FILE_BYTES + 1)
            .expect("extend sparse file");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(!vfs.exists("/large.bin"));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn seed_budget_stops_before_total_byte_limit() {
        let root = test_root("total");
        let file_path = root.join("small.txt");
        fs::write(&file_path, b"x").expect("write test file");

        let mut budget = SeedBudget {
            entries: 1,
            total_bytes: MAX_SEED_TOTAL_BYTES,
        };

        assert_eq!(budget.reserve_file(&file_path, 1), SeedDecision::Stop);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn seed_budget_stops_at_entry_limit() {
        let root = test_root("entries");
        let file_path = root.join("small.txt");
        fs::write(&file_path, b"x").expect("write test file");
        let mut budget = SeedBudget {
            entries: MAX_SEED_ENTRIES,
            total_bytes: 0,
        };

        assert_eq!(budget.reserve_file(&file_path, 1), SeedDecision::Stop);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn rename_rejects_moving_directory_into_its_own_child() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.rename("/pub", "/pub/docs/pub"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/pub/docs"));
        assert!(vfs.exists("/pub/readme.txt"));
        assert!(!vfs.exists("/pub/docs/pub"));
    }

    #[test]
    fn rename_rejects_directory_moves_to_root() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.rename("/pub", "/"));
        let children = vfs.list("/");
        assert!(
            children
                .iter()
                .any(|(name, is_dir, _)| name == "pub" && *is_dir)
        );
        assert!(
            children
                .iter()
                .any(|(name, is_dir, _)| name == "home" && *is_dir)
        );
        assert!(vfs.exists("/pub/docs"));
        assert!(vfs.exists("/pub/readme.txt"));
    }

    #[test]
    fn rename_rejects_root_directory_moves() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.rename("/", "/tmp/root"));
        assert!(vfs.exists("/"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/pub/readme.txt"));
        assert!(!vfs.exists("/tmp/root"));
    }

    #[test]
    fn delete_rejects_root_directory_removal() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.delete("/"));
        assert!(vfs.exists("/"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/home"));
        assert!(vfs.exists("/home/admin"));
    }

    #[test]
    fn normalize_path_resolves_dot_segments_for_public_operations() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_file("/pub/./docs/../note.txt", b"note".to_vec());

        assert!(vfs.exists("/pub/note.txt"));
        assert_eq!(vfs.get("/pub/../pub/note.txt"), Some(b"note".to_vec()));
        assert!(
            vfs.list("/pub/./")
                .iter()
                .any(|(name, is_dir, _)| name == "note.txt" && !*is_dir)
        );
    }

    #[test]
    fn public_operations_reject_control_characters_in_paths() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_file("/pub/bad\nname.txt", b"bad".to_vec());
        vfs.create_dir("/pub/bad\tname");

        assert!(!vfs.exists("/pub/bad\nname.txt"));
        assert!(!vfs.exists("/pub/bad\tname"));
        assert!(vfs.get("/pub/bad\nname.txt").is_none());
        assert!(vfs.list("/pub/bad\n").is_empty());
        assert!(!vfs.delete("/pub/bad\nname.txt"));
        assert!(!vfs.rename("/pub/readme.txt", "/pub/bad\nname.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn seeding_real_directories_rejects_control_characters_in_names() {
        use std::fs;

        let root = test_root("vfs-seed-control");
        fs::create_dir_all(&root).expect("create temp root");
        fs::create_dir(root.join("bad\nname")).expect("create control-char dir");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(!vfs.exists("/bad\nname"));
        assert!(
            vfs.list("/")
                .iter()
                .any(|(name, _, _)| name.starts_with("unnamed-"))
        );
        assert!(
            vfs.list("/")
                .iter()
                .all(|(name, _, _)| !name.as_bytes().iter().any(|byte| *byte < 0x20))
        );

        fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn create_file_rejects_root_path() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_file("/", b"root".to_vec());

        assert!(vfs.exists("/"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/home"));
        assert!(vfs.get("/").is_none());
    }

    #[test]
    fn create_file_preserves_existing_directories() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_file("/home", b"data".to_vec());

        assert!(vfs.exists("/home"));
        assert!(vfs.exists("/home/admin"));
        assert!(vfs.get("/home").is_none());
    }

    #[test]
    fn create_dir_preserves_existing_files() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_dir("/pub/readme.txt");

        assert!(vfs.exists("/pub/readme.txt"));
        assert!(vfs.get("/pub/readme.txt").is_some());
        assert!(!vfs.exists("/pub/readme.txt/docs"));
    }

    #[test]
    fn create_file_requires_existing_parent_directory() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_file("/missing/note.txt", b"note".to_vec());

        assert!(!vfs.exists("/missing"));
        assert!(!vfs.exists("/missing/note.txt"));
    }

    #[test]
    fn create_dir_requires_existing_parent_directory() {
        let vfs = VirtualFilesystem::new(None);

        vfs.create_dir("/missing/nested");

        assert!(!vfs.exists("/missing"));
        assert!(!vfs.exists("/missing/nested"));
    }

    #[test]
    fn default_syslog_content_uses_supplied_utc_time() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");

        assert_eq!(
            default_syslog_content(now),
            "Jan  1 00:00:00 localhost kernel: NetTrap VFS initialized\n"
        );
    }

    #[test]
    fn default_vfs_syslog_does_not_use_frozen_placeholder() {
        let vfs = VirtualFilesystem::new(None);
        let content = vfs.get("/var/log/syslog").expect("default syslog exists");
        let content = String::from_utf8(content).expect("default syslog should be UTF-8");

        assert!(content.contains(" localhost kernel: NetTrap VFS initialized\n"));
        assert!(!content.starts_with("Jan  1 00:00:00 "));
    }

    #[test]
    fn default_vfs_syslog_uses_faketime_offset() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);

        let vfs = VirtualFilesystem::new(None);
        let content = String::from_utf8(vfs.get("/var/log/syslog").expect("default syslog exists"))
            .expect("default syslog should be UTF-8");
        let expected = default_syslog_content(crate::faketime::fake_now());

        assert_eq!(content, expected);

        crate::faketime::set_delta(baseline);
    }

    #[test]
    fn delete_rejects_non_empty_directories() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.delete("/pub"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/pub/docs"));
        assert!(vfs.exists("/pub/readme.txt"));
    }

    #[test]
    fn rename_rejects_missing_destination_parent_directory() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.rename("/pub", "/missing/pub"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/pub/docs"));
        assert!(vfs.exists("/pub/readme.txt"));
    }

    #[test]
    fn rename_rejects_destination_overwrite() {
        let vfs = VirtualFilesystem::new(None);

        assert!(!vfs.rename("/pub", "/home"));
        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/home"));
        assert!(vfs.exists("/pub/readme.txt"));
        assert!(vfs.exists("/home/admin"));
        assert!(vfs.exists("/home/admin/.bashrc"));
    }

    #[cfg(unix)]
    #[test]
    fn seeding_skips_final_symlinks() {
        let root = test_root("symlink");
        let external = root
            .parent()
            .expect("test root should have a parent")
            .join(format!("nettrap-vfs-external-{}", uuid::Uuid::new_v4()));
        fs::write(&external, b"outside").expect("write external target");
        std::os::unix::fs::symlink(&external, root.join("linked.txt")).expect("create symlink");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(!vfs.exists("/linked.txt"));
        fs::remove_dir_all(root).expect("remove test root");
        fs::remove_file(external).expect("remove external file");
    }

    #[cfg(unix)]
    #[test]
    fn seeding_from_symlink_root_uses_default_entries() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink-root");
        let real_root = root.join("real");
        let linked_root = root.join("linked");
        fs::create_dir_all(&real_root).expect("create real root");
        fs::write(real_root.join("seed.txt"), b"seed").expect("write fixture");
        symlink(&real_root, &linked_root).expect("create root symlink");

        let vfs = VirtualFilesystem::new(linked_root.to_str());

        assert!(vfs.exists("/pub"));
        assert!(vfs.exists("/pub/readme.txt"));
        assert!(!vfs.exists("/seed.txt"));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn seeding_falls_back_for_non_utf8_file_names() {
        let root = test_root("nonutf8");
        let file_name = OsString::from_vec(b"entry-\xff".to_vec());
        fs::write(root.join(&file_name), b"fixture").expect("write fixture");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(
            vfs.list("/")
                .iter()
                .any(|(name, _, _)| name.starts_with("unnamed-"))
        );
        assert_eq!(
            vfs.get("/unnamed-656e7472792dff"),
            Some(b"fixture".to_vec())
        );

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn seeding_preserves_parent_directories_for_non_utf8_leaf_names() {
        let root = test_root("nested-nonutf8");
        let nested = root.join("assets");
        fs::create_dir_all(&nested).expect("create nested directory");
        let file_name = OsString::from_vec(b"entry-\xff.txt".to_vec());
        fs::write(nested.join(&file_name), b"fixture").expect("write fixture");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(vfs.exists("/assets/unnamed-656e7472792dff2e747874"));
        assert_eq!(
            vfs.get("/assets/unnamed-656e7472792dff2e747874"),
            Some(b"fixture".to_vec())
        );

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn seeding_keeps_distinct_non_utf8_names_separate() {
        let root = test_root("nonutf8-collision");
        let first = OsString::from_vec(b"entry-\xff".to_vec());
        let second = OsString::from_vec(b"entry-\xfe".to_vec());
        fs::write(root.join(&first), b"first").expect("write first fixture");
        fs::write(root.join(&second), b"second").expect("write second fixture");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert_eq!(vfs.get("/unnamed-656e7472792dff"), Some(b"first".to_vec()));
        assert_eq!(vfs.get("/unnamed-656e7472792dfe"), Some(b"second".to_vec()));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn seeding_preserves_utf8_names_with_surrounding_spaces() {
        let root = test_root("spaces");
        let file_name = "  entry name  .txt";
        fs::write(root.join(file_name), b"fixture").expect("write fixture");

        let vfs = VirtualFilesystem::new(root.to_str());

        assert!(vfs.exists("/  entry name  .txt"));
        assert_eq!(vfs.get("/  entry name  .txt"), Some(b"fixture".to_vec()));

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn read_seed_file_rejects_symlinked_parent_directory() {
        let root = test_root("parent-symlink");
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        fs::create_dir_all(&real_parent).expect("create real parent");
        fs::write(real_parent.join("seed.bin"), b"seed").expect("write seed file");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create parent symlink");

        let err = read_seed_file(&real_parent, &linked_parent.join("seed.bin"))
            .expect_err("symlinked parent should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn read_seed_file_rejects_symlinked_root_directory() {
        let root = test_root("root-symlink");
        let real_root = root.join("real");
        let linked_root = root.join("linked");
        fs::create_dir_all(&real_root).expect("create real root");
        fs::write(real_root.join("seed.bin"), b"seed").expect("write seed file");
        std::os::unix::fs::symlink(&real_root, &linked_root).expect("create root symlink");

        let err = read_seed_file(&linked_root, &linked_root.join("seed.bin"))
            .expect_err("symlinked root should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(root).expect("remove test root");
    }
}
