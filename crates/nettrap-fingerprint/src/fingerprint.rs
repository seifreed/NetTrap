use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha256Digest, Sha256};

pub fn compute_fingerprint(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub struct Fingerprint {
    pub sha256: String,
    pub md5: String,
    pub size: usize,
}

impl Fingerprint {
    pub fn compute(data: &[u8]) -> Self {
        Self {
            sha256: compute_sha256(data),
            md5: compute_md5(data),
            size: data.len(),
        }
    }
}
