use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const MAX_DUMPBIN_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

struct LimitedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

enum LimitedCommandStream {
    Content(Vec<u8>),
    TooLarge,
}

fn main() {
    if let Err(err) = run() {
        println!("cargo:warning={err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=LIB");
    println!("cargo:rerun-if-env-changed=PATH");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return Ok(());
    }

    println!("cargo:rustc-link-lib=delayimp");
    println!("cargo:rustc-link-arg-bin=nettrap=/DELAYLOAD:wpcap.dll");

    if let Some(dll_dir) = find_npcap_dir() {
        let profile_dir = output_profile_dir()?;
        copy_runtime_dlls(&dll_dir, &profile_dir)?;

        let lib_dir = ensure_wpcap_import_lib(&dll_dir)?;
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        return Ok(());
    }

    if let Some(lib_dir) = find_wpcap_import_lib_dir() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        return Ok(());
    }

    Err(
        "Npcap ARM64 runtime or wpcap.lib not found. Install Npcap or provide its SDK through LIB"
            .to_string(),
    )
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

fn find_wpcap_import_lib_dir() -> Option<PathBuf> {
    let lib_env = env::var_os("LIB")?;
    env::split_paths(&lib_env).find(|dir| dir.join("wpcap.lib").exists())
}

fn output_profile_dir() -> Result<PathBuf, String> {
    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "OUT_DIR not set".to_string())?;
    out_dir
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .ok_or_else(|| "Failed to resolve target profile directory".to_string())
}

fn copy_runtime_dlls(dll_dir: &Path, profile_dir: &Path) -> Result<(), String> {
    for file_name in ["Packet.dll", "wpcap.dll", "wpcap_arm64.dll"] {
        let source = dll_dir.join(file_name);
        if source.exists() {
            let destination = profile_dir.join(file_name);
            fs::copy(&source, &destination).map_err(|err| {
                format!(
                    "Failed to copy {} to {}: {}",
                    source.display(),
                    destination.display(),
                    err
                )
            })?;
        }
    }

    let arm64_packet = dll_dir.join("Packet_arm64.dll");
    if arm64_packet.exists() {
        let destination = profile_dir.join("Packet_arm64.dll");
        fs::copy(&arm64_packet, &destination).map_err(|err| {
            format!(
                "Failed to copy {} to {}: {}",
                arm64_packet.display(),
                destination.display(),
                err
            )
        })?;
    }

    Ok(())
}

fn ensure_wpcap_import_lib(dll_dir: &Path) -> Result<PathBuf, String> {
    for dir in candidate_lib_dirs(dll_dir) {
        if dir.join("wpcap.lib").exists() {
            return Ok(dir);
        }
    }

    let dll_path = dll_dir.join("wpcap_arm64.dll");
    if !dll_path.exists() {
        return Err(format!(
            "Npcap ARM64 DLL not found at {}. Install the ARM64 Npcap runtime.",
            dll_path.display()
        ));
    }

    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "OUT_DIR not set".to_string())?;
    let import_dir = out_dir.join("npcap-arm64");
    fs::create_dir_all(&import_dir).map_err(|err| {
        format!(
            "Failed to create ARM64 import-lib directory {}: {}",
            import_dir.display(),
            err
        )
    })?;

    let def_path = import_dir.join("wpcap.def");
    let lib_path = import_dir.join("wpcap.lib");

    let exports = dump_exports(&dll_path)?;
    let mut def_contents = String::from("LIBRARY wpcap_arm64.dll\nEXPORTS\n");
    for export in exports {
        def_contents.push_str(&export);
        def_contents.push('\n');
    }
    fs::write(&def_path, def_contents)
        .map_err(|err| format!("Failed to write generated wpcap.def: {err}"))?;

    let lib_exe = resolve_msvc_tool("lib.exe")?;
    let def_arg = prefixed_path_arg("/def:", &def_path);
    let out_arg = prefixed_path_arg("/out:", &lib_path);
    let status = Command::new(&lib_exe)
        .args([def_arg, OsString::from("/machine:ARM64"), out_arg])
        .status()
        .map_err(|err| format!("Failed to run lib.exe to generate wpcap.lib: {err}"))?;

    if !status.success() {
        return Err("lib.exe failed while generating ARM64 wpcap.lib".to_string());
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

fn dump_exports(dll_path: &Path) -> Result<Vec<String>, String> {
    let dumpbin = resolve_msvc_tool("dumpbin.exe")?;
    let mut command = Command::new(&dumpbin);
    command.arg("/EXPORTS").arg(dll_path);
    let output =
        run_command_with_limited_stdout(command, "dumpbin.exe /EXPORTS", MAX_DUMPBIN_OUTPUT_BYTES)
            .map_err(|err| format!("Failed to run dumpbin.exe to inspect Npcap exports: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "dumpbin.exe failed while reading {}",
            dll_path.display()
        ));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        format!(
            "dumpbin.exe produced invalid UTF-8 for {}: {}",
            dll_path.display(),
            err
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
        return Err(format!("No exports found in {}", dll_path.display()));
    }

    Ok(exports)
}

fn run_command_with_limited_stdout(
    mut command: Command,
    label: &str,
    stdout_limit: usize,
) -> Result<LimitedCommandOutput, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("{label} failed: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout pipe was not available"))?;

    let stdout_reader =
        std::thread::spawn(move || read_limited_command_stream(stdout, stdout_limit));
    let status = child
        .wait()
        .map_err(|err| format!("{label} wait failed: {err}"))?;
    let stdout = join_limited_reader(stdout_reader, label, "stdout")?;
    let stdout = match stdout {
        LimitedCommandStream::Content(stdout) => stdout,
        LimitedCommandStream::TooLarge => {
            return Err(format!("{label} stdout exceeded {stdout_limit} byte limit"));
        }
    };

    Ok(LimitedCommandOutput { status, stdout })
}

fn join_limited_reader(
    handle: std::thread::JoinHandle<io::Result<LimitedCommandStream>>,
    label: &str,
    stream_name: &str,
) -> Result<LimitedCommandStream, String> {
    handle
        .join()
        .map_err(|_| format!("{label} {stream_name} reader panicked"))?
        .map_err(|err| format!("{label} {stream_name} read failed: {err}"))
}

fn read_limited_command_stream<R: Read>(
    reader: R,
    max_bytes: usize,
) -> io::Result<LimitedCommandStream> {
    let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command output limit is not representable as u64",
        )
    })?;
    let _limit = max_bytes_u64.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "command output limit sentinel overflowed",
        )
    })?;
    let mut content = Vec::new();
    let mut reader = reader;
    let mut buffer = [0u8; 8192];
    let mut too_large = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let previous_len = content.len();
        if content.len() < max_bytes {
            let retained = (max_bytes - content.len()).min(read);
            content.extend_from_slice(&buffer[..retained]);
        }
        if previous_len.saturating_add(read) > max_bytes {
            too_large = true;
        }
    }
    if too_large {
        return Ok(LimitedCommandStream::TooLarge);
    }
    Ok(LimitedCommandStream::Content(content))
}

fn prefixed_path_arg(prefix: &str, path: &Path) -> OsString {
    let mut arg = OsString::from(prefix);
    arg.push(path);
    arg
}

fn resolve_msvc_tool(tool_name: &str) -> Result<PathBuf, String> {
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
    let mut entries = match fs::read_dir(&vs_root) {
        Ok(entries) => entries,
        Err(err) => {
            return Err(format!(
                "Visual Studio tools not found; unable to locate {} under {}: {}",
                tool_name,
                vs_root.display(),
                err
            ));
        }
    };

    while let Some(year) = entries.next().transpose().map_err(|err| err.to_string())? {
        if !year.path().is_dir() {
            continue;
        }

        let mut editions = match fs::read_dir(year.path()) {
            Ok(editions) => editions,
            Err(err) => {
                return Err(format!(
                    "failed to read Visual Studio edition directory '{}': {}",
                    year.path().display(),
                    err
                ));
            }
        };
        while let Some(edition) = editions.next().transpose().map_err(|err| err.to_string())? {
            if !edition.path().is_dir() {
                continue;
            }

            let tools_root = edition.path().join("VC").join("Tools").join("MSVC");
            if !tools_root.exists() {
                continue;
            }

            let mut versions = match fs::read_dir(&tools_root) {
                Ok(versions) => versions,
                Err(err) => {
                    return Err(format!(
                        "failed to read MSVC tools directory '{}': {}",
                        tools_root.display(),
                        err
                    ));
                }
            };
            while let Some(version) = versions.next().transpose().map_err(|err| err.to_string())? {
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

    Err(format!("Unable to locate {tool_name}"))
}
