//! Virtual Filesystem (VFS) — provides a fake filesystem for honeypot services
//! (FTP, TFTP, SMB, etc.) without exposing real host files.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;

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
            if path.is_dir() {
                vfs.seed_from_dir(path, path);
                return vfs;
            }
        }

        // Populate default virtual entries
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
            b"Jan  1 00:00:00 localhost kernel: NetTrap VFS initialized\n".to_vec(),
        );

        vfs
    }

    /// Seed VFS entries from a real directory tree (max depth to prevent symlink cycles)
    fn seed_from_dir(&self, base: &Path, current: &Path) {
        self.seed_from_dir_depth(base, current, 0);
    }

    fn seed_from_dir_depth(&self, base: &Path, current: &Path, depth: usize) {
        const MAX_DEPTH: usize = 20;
        if depth > MAX_DEPTH {
            tracing::warn!(
                "VFS seed_from_dir: max depth {} reached at {:?}, stopping (possible symlink cycle)",
                MAX_DEPTH,
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
        if let Ok(entries) = std::fs::read_dir(current) {
            let relative = current.strip_prefix(base).unwrap_or(Path::new(""));
            let vfs_dir = format!("/{}", relative.to_string_lossy());
            let vfs_dir = Self::normalize_path(&vfs_dir);
            self.create_dir_internal(&vfs_dir);

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.seed_from_dir_depth(base, &path, depth + 1);
                } else if path.is_file() {
                    let rel = path.strip_prefix(base).unwrap_or(&path);
                    let vfs_path = format!("/{}", rel.to_string_lossy());
                    let vfs_path = Self::normalize_path(&vfs_path);
                    if let Ok(content) = std::fs::read(&path) {
                        self.create_file_internal(&vfs_path, content);
                    }
                }
            }
        }
    }

    fn normalize_path(path: &str) -> String {
        let p = path.replace('\\', "/");
        let p = if p.starts_with('/') {
            p
        } else {
            format!("/{}", p)
        };
        // Remove double slashes
        let mut result = String::with_capacity(p.len());
        let mut last_was_slash = false;
        for ch in p.chars() {
            if ch == '/' {
                if !last_was_slash {
                    result.push('/');
                }
                last_was_slash = true;
            } else {
                result.push(ch);
                last_was_slash = false;
            }
        }
        // Remove trailing slash unless it's root
        if result.len() > 1 && result.ends_with('/') {
            result.pop();
        }
        result
    }

    fn create_dir_internal(&self, path: &str) {
        let path = Self::normalize_path(path);
        self.entries.write().insert(path, VfsEntry::Directory);
    }

    fn create_file_internal(&self, path: &str, content: Vec<u8>) {
        let path = Self::normalize_path(path);
        let size = content.len() as u64;
        self.entries
            .write()
            .insert(path, VfsEntry::File { content, size });
    }

    /// List entries in a directory. Returns (name, is_dir, size) tuples.
    pub fn list(&self, path: &str) -> Vec<(String, bool, u64)> {
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
                // Only direct children (no further slashes after prefix)
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
        let path = Self::normalize_path(path);
        let entries = self.entries.read();
        match entries.get(&path) {
            Some(VfsEntry::File { content, .. }) => Some(content.clone()),
            _ => None,
        }
    }

    /// Create a file in the VFS
    pub fn create_file(&self, path: &str, content: Vec<u8>) {
        self.create_file_internal(path, content);
    }

    /// Create a directory in the VFS
    pub fn create_dir(&self, path: &str) {
        self.create_dir_internal(path);
    }

    /// Delete an entry
    pub fn delete(&self, path: &str) -> bool {
        let path = Self::normalize_path(path);
        self.entries.write().remove(&path).is_some()
    }

    /// Check if an entry exists
    pub fn exists(&self, path: &str) -> bool {
        let path = Self::normalize_path(path);
        self.entries.read().contains_key(&path)
    }

    /// Rename / move an entry (updates children for directory renames)
    pub fn rename(&self, from: &str, to: &str) -> bool {
        let from = Self::normalize_path(from);
        let to = Self::normalize_path(to);
        let mut entries = self.entries.write();
        if let Some(entry) = entries.remove(&from) {
            let is_dir = entry.is_dir();
            entries.insert(to.clone(), entry);
            // Re-key all children under the old prefix
            if is_dir {
                let from_prefix = format!("{}/", from);
                let children: Vec<(String, VfsEntry)> = entries
                    .iter()
                    .filter(|(k, _)| k.starts_with(&from_prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (old_key, child_entry) in children {
                    entries.remove(&old_key);
                    let new_key = format!("{}/{}", to, &old_key[from_prefix.len()..]);
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
