// On Windows ARM64 the `pcap` crate links against `wpcap.lib`, but Npcap ships
// only `wpcap_arm64.dll` (no import library). `nettrap-cli` generates an ARM64
// `wpcap.lib` for its own binary, but that link-search path does not propagate
// to this crate's own build artifacts — most notably the `nettrap-interceptor`
// test harness, which links `wpcap.lib` directly and otherwise fails with
// `LNK1181: cannot open input file 'wpcap.lib'`. This build script ensures the
// import library exists and adds its directory to the link search path so that
// `cargo test -p nettrap-interceptor` (and `cargo test --workspace`) link.
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type BuildResult<T> = Result<T, Box<dyn Error>>;

fn main() -> BuildResult<()> {
    println!("cargo:rerun-if-env-changed=LIB");
    println!("cargo:rerun-if-env-changed=PATH");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return Ok(());
    }

    let Some(dll_dir) = find_npcap_dir() else {
        // No ARM64 Npcap runtime available; leave linking to whatever the
        // environment provides (LIB, etc.). Emitting nothing keeps non-Npcap
        // setups building when they supply their own wpcap.lib.
        return Ok(());
    };

    let lib_dir = ensure_wpcap_import_lib(&dll_dir)?;
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    Ok(())
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

fn ensure_wpcap_import_lib(dll_dir: &Path) -> BuildResult<PathBuf> {
    for dir in candidate_lib_dirs(dll_dir) {
        if dir.join("wpcap.lib").exists() {
            return Ok(dir);
        }
    }

    let dll_path = ["wpcap_arm64.dll", "wpcap.dll"]
        .into_iter()
        .map(|name| dll_dir.join(name))
        .find(|path| path.exists())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Npcap DLL not found under {}. Install the ARM64 Npcap runtime.",
                    dll_dir.display()
                ),
            )
        })?;

    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR not set"))?;
    let import_dir = out_dir.join("npcap-arm64");
    fs::create_dir_all(&import_dir).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to create ARM64 import-lib directory '{}': {}",
                import_dir.display(),
                err
            ),
        )
    })?;

    let def_path = import_dir.join("wpcap.def");
    let lib_path = import_dir.join("wpcap.lib");

    let exports = dump_exports(&dll_path)?;
    let mut def_contents = format!(
        "LIBRARY {}\nEXPORTS\n",
        dll_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Npcap DLL filename '{}'", dll_path.display()),
                )
            })?
    );
    for export in exports {
        def_contents.push_str(&export);
        def_contents.push('\n');
    }
    fs::write(&def_path, def_contents).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to write generated definition file '{}': {}",
                def_path.display(),
                err
            ),
        )
    })?;

    let lib_exe = resolve_msvc_tool("lib.exe")?;
    let status = Command::new(&lib_exe)
        .args([
            format!("/def:{}", def_path.display()),
            "/machine:ARM64".to_string(),
            format!("/out:{}", lib_path.display()),
        ])
        .status()
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to run '{}' to generate wpcap.lib: {}",
                    lib_exe.display(),
                    err
                ),
            )
        })?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "lib.exe failed while generating ARM64 wpcap.lib with status {status}"
        ))
        .into());
    }

    Ok(import_dir)
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

fn dump_exports(dll_path: &Path) -> BuildResult<Vec<String>> {
    let dumpbin = resolve_msvc_tool("dumpbin.exe")?;
    let output = Command::new(&dumpbin)
        .args(["/EXPORTS", &dll_path.display().to_string()])
        .output()
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to run '{}' to inspect Npcap exports from '{}': {}",
                    dumpbin.display(),
                    dll_path.display(),
                    err
                ),
            )
        })?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "dumpbin.exe failed while reading '{}' with status {}",
            dll_path.display(),
            output.status
        ))
        .into());
    }

    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "dumpbin.exe produced invalid UTF-8 while reading '{}': {}",
                dll_path.display(),
                err
            ),
        )
    })?;
    let mut exports = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0].chars().all(|c| c.is_ascii_digit()) {
            exports.push(parts[3].to_string());
        }
    }

    if exports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no exports found in '{}'", dll_path.display()),
        )
        .into());
    }

    Ok(exports)
}

fn resolve_msvc_tool(tool_name: &str) -> BuildResult<PathBuf> {
    if let Some(path) = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(tool_name))
            .find(|candidate| candidate.exists())
    }) {
        return Ok(path);
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
    let entries = fs::read_dir(&vs_root).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "Visual Studio tools not found; unable to locate {} under {}: {}",
                tool_name,
                vs_root.display(),
                err
            ),
        )
    })?;

    for year in entries {
        let year = year.map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read Visual Studio installation entry under '{}': {}",
                    vs_root.display(),
                    err
                ),
            )
        })?;
        let editions = fs::read_dir(year.path()).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read Visual Studio edition directory '{}': {}",
                    year.path().display(),
                    err
                ),
            )
        })?;
        for edition in editions {
            let edition = edition.map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "failed to read Visual Studio edition entry under '{}': {}",
                        year.path().display(),
                        err
                    ),
                )
            })?;
            let tools_root = edition.path().join("VC").join("Tools").join("MSVC");
            if !tools_root.exists() {
                continue;
            }

            let versions = fs::read_dir(&tools_root).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "failed to read MSVC tools directory '{}': {}",
                        tools_root.display(),
                        err
                    ),
                )
            })?;
            for version in versions {
                let version = version.map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!(
                            "failed to read MSVC version entry under '{}': {}",
                            tools_root.display(),
                            err
                        ),
                    )
                })?;
                let preferred = version
                    .path()
                    .join("bin")
                    .join(host_dir)
                    .join("arm64")
                    .join(tool_name);
                if preferred.exists() {
                    return Ok(preferred);
                }

                let fallback = version
                    .path()
                    .join("bin")
                    .join("Hostx64")
                    .join("arm64")
                    .join(tool_name);
                if fallback.exists() {
                    return Ok(fallback);
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("unable to locate {} under {}", tool_name, vs_root.display()),
    )
    .into())
}
