use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LIB");
    println!("cargo:rerun-if-env-changed=PATH");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return;
    }

    let dll_dir = find_npcap_dir().unwrap_or_else(|| {
        panic!("Npcap ARM64 runtime not found. Expected files under C:\\Windows\\System32\\Npcap")
    });

    println!("cargo:rustc-link-lib=delayimp");
    println!("cargo:rustc-link-arg-bin=nettrap=/DELAYLOAD:wpcap_arm64.dll");

    let profile_dir = output_profile_dir();
    copy_runtime_dlls(&dll_dir, &profile_dir);

    let lib_dir = ensure_wpcap_import_lib(&dll_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
}

fn find_npcap_dir() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(r"C:\Windows\System32\Npcap"),
        PathBuf::from(r"C:\Program Files\Npcap"),
    ];

    candidates.into_iter().find(|dir| {
        dir.join("Packet.dll").exists()
            && (dir.join("wpcap_arm64.dll").exists() || dir.join("wpcap.dll").exists())
    })
}

fn output_profile_dir() -> PathBuf {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    out_dir
        .ancestors()
        .nth(3)
        .expect("Failed to resolve target profile directory")
        .to_path_buf()
}

fn copy_runtime_dlls(dll_dir: &Path, profile_dir: &Path) {
    for file_name in ["Packet.dll", "wpcap.dll", "wpcap_arm64.dll"] {
        let source = dll_dir.join(file_name);
        if source.exists() {
            let destination = profile_dir.join(file_name);
            fs::copy(&source, &destination).unwrap_or_else(|err| {
                panic!(
                    "Failed to copy {} to {}: {}",
                    source.display(),
                    destination.display(),
                    err
                )
            });
        }
    }

    let arm64_packet = dll_dir.join("Packet_arm64.dll");
    if arm64_packet.exists() {
        let destination = profile_dir.join("Packet_arm64.dll");
        fs::copy(&arm64_packet, &destination).unwrap_or_else(|err| {
            panic!(
                "Failed to copy {} to {}: {}",
                arm64_packet.display(),
                destination.display(),
                err
            )
        });
    }
}

fn ensure_wpcap_import_lib(dll_dir: &Path) -> PathBuf {
    for dir in candidate_lib_dirs(dll_dir) {
        if dir.join("wpcap.lib").exists() {
            return dir;
        }
    }

    let dll_path = dll_dir.join("wpcap_arm64.dll");
    if !dll_path.exists() {
        panic!(
            "Npcap ARM64 DLL not found at {}. Install the ARM64 Npcap runtime.",
            dll_path.display()
        );
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let import_dir = out_dir.join("npcap-arm64");
    fs::create_dir_all(&import_dir).expect("Failed to create ARM64 import-lib directory");

    let def_path = import_dir.join("wpcap.def");
    let lib_path = import_dir.join("wpcap.lib");

    let exports = dump_exports(&dll_path);
    let mut def_contents = String::from("LIBRARY wpcap_arm64.dll\nEXPORTS\n");
    for export in exports {
        def_contents.push_str(&export);
        def_contents.push('\n');
    }
    fs::write(&def_path, def_contents).expect("Failed to write generated wpcap.def");

    let lib_exe = resolve_msvc_tool("lib.exe");
    let status = Command::new(&lib_exe)
        .args([
            format!("/def:{}", def_path.display()),
            "/machine:ARM64".to_string(),
            format!("/out:{}", lib_path.display()),
        ])
        .status()
        .expect("Failed to run lib.exe to generate wpcap.lib");

    if !status.success() {
        panic!("lib.exe failed while generating ARM64 wpcap.lib");
    }

    import_dir
}

fn candidate_lib_dirs(dll_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(lib_env) = env::var_os("LIB") {
        dirs.extend(env::split_paths(&lib_env));
    }

    dirs.push(dll_dir.to_path_buf());
    dirs.push(PathBuf::from(r"C:\Program Files\Npcap\Lib\ARM64"));
    dirs.push(PathBuf::from(r"C:\Program Files\Npcap\Lib"));
    dirs
}

fn dump_exports(dll_path: &Path) -> Vec<String> {
    let dumpbin = resolve_msvc_tool("dumpbin.exe");
    let output = Command::new(&dumpbin)
        .args(["/EXPORTS", &dll_path.display().to_string()])
        .output()
        .expect("Failed to run dumpbin.exe to inspect Npcap exports");

    if !output.status.success() {
        panic!("dumpbin.exe failed while reading {}", dll_path.display());
    }

    let stdout = String::from_utf8(output.stdout).expect("dumpbin.exe produced invalid UTF-8");
    let mut exports = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0].chars().all(|c| c.is_ascii_digit()) {
            exports.push(parts[3].to_string());
        }
    }

    if exports.is_empty() {
        panic!("No exports found in {}", dll_path.display());
    }

    exports
}

fn resolve_msvc_tool(tool_name: &str) -> PathBuf {
    if let Some(path) = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(tool_name))
            .find(|candidate| candidate.exists())
    }) {
        return path;
    }

    let host_arch = env::var("HOST")
        .ok()
        .and_then(|host| host.split('-').next().map(str::to_owned))
        .unwrap_or_else(|| "aarch64".to_string());
    let host_dir = if host_arch.contains("aarch64") {
        "Hostarm64"
    } else {
        "Hostx64"
    };

    let vs_root = PathBuf::from(r"C:\Program Files\Microsoft Visual Studio");
    let entries = fs::read_dir(&vs_root).unwrap_or_else(|_| {
        panic!(
            "Visual Studio tools not found; unable to locate {} under {}",
            tool_name,
            vs_root.display()
        )
    });

    for year in entries.flatten() {
        for edition in fs::read_dir(year.path()).into_iter().flatten().flatten() {
            let tools_root = edition.path().join("VC").join("Tools").join("MSVC");
            if !tools_root.exists() {
                continue;
            }

            for version in fs::read_dir(&tools_root).into_iter().flatten().flatten() {
                let preferred = version
                    .path()
                    .join("bin")
                    .join(host_dir)
                    .join("arm64")
                    .join(tool_name);
                if preferred.exists() {
                    return preferred;
                }

                let fallback = version
                    .path()
                    .join("bin")
                    .join("Hostx64")
                    .join("arm64")
                    .join(tool_name);
                if fallback.exists() {
                    return fallback;
                }
            }
        }
    }

    panic!("Unable to locate {}", tool_name);
}
