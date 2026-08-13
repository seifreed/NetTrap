#[path = "../src/dll.rs"]
mod dll;

#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
#[test]
fn trusted_dll_candidate_accepts_regular_file() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-windivert-regular-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join("WinDivert.dll");
    std::fs::write(&path, b"dll").expect("write dll");

    assert!(dll::is_trusted_dll_candidate(&path));

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn trusted_dll_candidate_rejects_symlink() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-windivert-symlink-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let real_parent = root.join("real");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    let target = real_parent.join("WinDivert.dll");
    std::fs::write(&target, b"dll").expect("write dll");
    let link = root.join("WinDivert.dll");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");

    assert!(!dll::is_trusted_dll_candidate(&link));

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(not(windows))]
#[test]
fn non_windows_loader_returns_empty_defaults() {
    assert!(dll::windivert_dll::find_windivert_dll().is_none());
    assert_eq!(dll::windivert_dll::get_driver_name(), "");
}

#[cfg(windows)]
#[test]
fn windows_loader_returns_dll_and_driver_names() {
    assert!(dll::windivert_dll::find_windivert_dll().is_some());
    assert!(!dll::windivert_dll::get_driver_name().is_empty());
}
