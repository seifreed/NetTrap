#[cfg(windows)]
fn main() {
    // Tell cargo to link against WinDivert
    // The DLL should be placed in the windivert/ directory or in PATH

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let windivert_dir = std::path::Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("windivert"));

    if let Some(dir) = windivert_dir {
        // Add windivert directory to the library search path
        println!("cargo:rustc-link-search=native={}", dir.display());

        // Tell cargo to rerun if windivert files change
        let dll_path = dir.join("WinDivert.dll");
        let sys_path = dir.join("WinDivert64.sys");

        if dll_path.exists() {
            println!("cargo:rerun-if-changed={}", dll_path.display());
        }
        if sys_path.exists() {
            println!("cargo:rerun-if-changed={}", sys_path.display());
        }
    }

    // Link against WinDivert
    println!("cargo:rustc-link-lib=dylib=WinDivert");
}

#[cfg(not(windows))]
fn main() {
    // No special build steps for non-Windows platforms
}
