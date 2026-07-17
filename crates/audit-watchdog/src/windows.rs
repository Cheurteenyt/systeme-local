use std::path::Path;

use crate::error::VerificationError;
use crate::model::WindowsVerificationReport;

/// Verifies the portable witnesses, hardened NTFS ACLs, and bootstrap Event Log entry.
///
/// The Windows implementation takes the existing runtime lock before reading the
/// receipt, anchor, ACLs, and Event Log witness. It never reads `.env` contents
/// or any HMAC key.
///
/// # Errors
///
/// Returns [`VerificationError`] when the platform is unsupported, the runtime
/// lock cannot be acquired, the portable witnesses fail, the metadata collector
/// fails, or the Windows witnesses do not match the bootstrap receipt.
pub fn verify_windows_project_root(
    project_root: &Path,
) -> Result<WindowsVerificationReport, VerificationError> {
    #[cfg(windows)]
    {
        platform::verify(project_root)
    }

    #[cfg(not(windows))]
    {
        let _ = project_root;
        Err(VerificationError::UnsupportedPlatform {
            feature: "Windows audit-witness verification",
        })
    }
}

#[cfg(windows)]
mod platform {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, OpenOptions, TryLockError};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use std::os::windows::process::CommandExt as _;

    use crate::error::VerificationError;
    use crate::model::WindowsVerificationReport;
    use crate::verify::{ensure_regular_file, verify_project_root_with_receipt};
    use crate::windows_contract::{WindowsSnapshot, validate_windows_snapshot};

    const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
    const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);
    const LOCK_TIMEOUT_SECONDS: u64 = 5;
    const MAX_COLLECTOR_OUTPUT_BYTES: usize = 1024 * 1024;
    const MAX_COLLECTOR_ERROR_BYTES: usize = 4096;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const COLLECTOR_SCRIPT: &str = include_str!("windows_snapshot.ps1");

    pub(super) fn verify(
        project_root: &Path,
    ) -> Result<WindowsVerificationReport, VerificationError> {
        let canonical_project = fs::canonicalize(project_root).map_err(|error| {
            VerificationError::io("canonicalizing project root", project_root, error)
        })?;
        if !canonical_project.is_dir() {
            return Err(VerificationError::windows_witness(
                "project root must be a directory",
            ));
        }

        let lock_path = canonical_project
            .join(".systeme-local")
            .join("audit-anchor")
            .join("audit-anchor.jsonl.lock");
        let lock_file = acquire_runtime_lock(&lock_path)?;

        let verification = (|| {
            let verified = verify_project_root_with_receipt(&canonical_project)?;
            let snapshot = collect_snapshot(&canonical_project)?;
            validate_windows_snapshot(
                &canonical_project,
                &verified.receipt,
                verified.report,
                &snapshot,
            )
        })();

        let unlock_result = lock_file
            .unlock()
            .map_err(|error| VerificationError::io("unlocking anchor lock", &lock_path, error));

        match (verification, unlock_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn acquire_runtime_lock(path: &Path) -> Result<File, VerificationError> {
        ensure_regular_file(path)?;
        ensure_direct_file(path)?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| VerificationError::io("opening anchor lock", path, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| VerificationError::io("reading anchor lock metadata", path, error))?;
        if !metadata.is_file() || metadata.len() < 1 {
            return Err(VerificationError::windows_witness(
                "anchor lock must be a non-empty regular file",
            ));
        }

        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(VerificationError::LockTimeout {
                            path: path.to_path_buf(),
                            seconds: LOCK_TIMEOUT_SECONDS,
                        });
                    }
                    thread::sleep(LOCK_POLL_INTERVAL.min(deadline - now));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(VerificationError::io("acquiring anchor lock", path, error));
                }
            }
        }
    }

    fn ensure_direct_file(path: &Path) -> Result<(), VerificationError> {
        let parent = path.parent().ok_or_else(|| {
            VerificationError::windows_witness("anchor lock has no parent directory")
        })?;
        let file_name = path
            .file_name()
            .ok_or_else(|| VerificationError::windows_witness("anchor lock has no file name"))?;
        let canonical_parent = fs::canonicalize(parent).map_err(|error| {
            VerificationError::io("canonicalizing anchor lock parent", parent, error)
        })?;
        let canonical_file = fs::canonicalize(path)
            .map_err(|error| VerificationError::io("canonicalizing anchor lock", path, error))?;
        let expected = canonical_parent.join(file_name);
        if !paths_equal(&expected, &canonical_file) {
            return Err(VerificationError::UnsafeFileType {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn collect_snapshot(project_root: &Path) -> Result<WindowsSnapshot, VerificationError> {
        let system_root = env::var_os("SystemRoot")
            .ok_or_else(|| VerificationError::windows_collector("SystemRoot is unavailable"))?;
        let system_root_path = PathBuf::from(system_root.clone());
        let system32 = system_root_path.join("System32");
        let powershell_home = system32.join("WindowsPowerShell").join("v1.0");
        let powershell = powershell_home.join("powershell.exe");
        ensure_regular_file(&powershell)?;

        let output = build_collector_command(
            &powershell,
            &powershell_home,
            &system32,
            &system_root,
            project_root,
        )
        .output()
        .map_err(|error| {
            VerificationError::io("running Windows witness collector", &powershell, error)
        })?;
        parse_collector_output(&output)
    }

    fn build_collector_command(
        powershell: &Path,
        powershell_home: &Path,
        system32: &Path,
        system_root: &OsStr,
        project_root: &Path,
    ) -> Command {
        let modules = powershell_home.join("Modules");
        let mut search_path = OsString::from(system32.as_os_str());
        search_path.push(";");
        search_path.push(powershell_home.as_os_str());
        let encoded_command = encode_powershell_command(COLLECTOR_SCRIPT);

        let mut command = Command::new(powershell);
        command
            .arg(OsStr::new("-NoLogo"))
            .arg(OsStr::new("-NoProfile"))
            .arg(OsStr::new("-NonInteractive"))
            .arg(OsStr::new("-ExecutionPolicy"))
            .arg(OsStr::new("Bypass"))
            .arg(OsStr::new("-OutputFormat"))
            .arg(OsStr::new("Text"))
            .arg(OsStr::new("-EncodedCommand"))
            .arg(encoded_command)
            .current_dir(project_root)
            .env_clear()
            .env("SystemRoot", system_root)
            .env("WINDIR", system_root)
            .env("COMSPEC", system32.join("cmd.exe"))
            .env("PATH", search_path)
            .env("PATHEXT", ".COM;.EXE;.BAT;.CMD")
            .env("PSModulePath", modules)
            .env("SLG_WATCHDOG_PROJECT_ROOT", project_root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);

        for name in [
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "SystemDrive",
            "HOMEDRIVE",
            "HOMEPATH",
        ] {
            copy_environment(&mut command, name);
        }
        command
    }

    fn parse_collector_output(output: &Output) -> Result<WindowsSnapshot, VerificationError> {
        if output.stdout.len() > MAX_COLLECTOR_OUTPUT_BYTES
            || output.stderr.len() > MAX_COLLECTOR_OUTPUT_BYTES
        {
            return Err(VerificationError::windows_collector(
                "collector output exceeded the one-megabyte limit",
            ));
        }

        let stderr = bounded_text(&output.stderr, MAX_COLLECTOR_ERROR_BYTES);
        if !output.status.success() {
            let code = output
                .status
                .code()
                .map_or_else(|| "terminated".to_owned(), |value| value.to_string());
            return Err(VerificationError::windows_collector(format!(
                "PowerShell exited with {code}: {stderr}"
            )));
        }

        let stdout = std::str::from_utf8(&output.stdout).map_err(|error| {
            VerificationError::windows_collector(format!("collector output is not UTF-8: {error}"))
        })?;
        let payload = stdout.trim().trim_start_matches('\u{feff}');
        if payload.is_empty() {
            return Err(VerificationError::windows_collector(
                "PowerShell produced no JSON output",
            ));
        }
        let snapshot = serde_json::from_str(payload).map_err(|error| {
            VerificationError::windows_collector(format!(
                "collector output is not valid JSON: {error}"
            ))
        })?;

        if !stderr.trim().is_empty() && !is_benign_progress_clixml(&output.stderr) {
            return Err(VerificationError::windows_collector(format!(
                "PowerShell wrote to stderr: {stderr}"
            )));
        }
        Ok(snapshot)
    }

    fn is_benign_progress_clixml(bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        let trimmed = text.trim().trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            return true;
        }

        let Some(xml) = trimmed.strip_prefix("#< CLIXML") else {
            return false;
        };
        let xml = xml.trim();
        if !xml.starts_with("<Objs ") || !xml.ends_with("</Objs>") {
            return false;
        }

        let mut remaining = xml;
        let mut progress_records = 0_usize;
        while let Some(index) = remaining.find(" S=\"") {
            let value = &remaining[index + 4..];
            let Some(end) = value.find('"') else {
                return false;
            };
            if &value[..end] != "progress" {
                return false;
            }
            progress_records += 1;
            remaining = &value[end + 1..];
        }
        progress_records > 0
    }

    fn encode_powershell_command(script: &str) -> String {
        let mut utf16le = Vec::with_capacity(script.len().saturating_mul(2));
        for unit in script.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        encode_base64(&utf16le)
    }

    fn encode_base64(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut encoded = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
        for chunk in input.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);

            encoded.push(char::from(TABLE[usize::from(first >> 2)]));
            encoded.push(char::from(
                TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
            ));

            if chunk.len() > 1 {
                encoded.push(char::from(
                    TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))],
                ));
            } else {
                encoded.push('=');
            }

            if chunk.len() > 2 {
                encoded.push(char::from(TABLE[usize::from(third & 0x3f)]));
            } else {
                encoded.push('=');
            }
        }
        encoded
    }

    fn copy_environment(command: &mut Command, name: &str) {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }

    fn bounded_text(bytes: &[u8], limit: usize) -> String {
        let bounded = bytes.get(..limit).unwrap_or(bytes);
        String::from_utf8_lossy(bounded).replace(['\r', '\n'], " ")
    }

    fn paths_equal(left: &Path, right: &Path) -> bool {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }

    #[cfg(test)]
    mod tests {
        use super::{encode_powershell_command, is_benign_progress_clixml};

        #[test]
        fn encodes_windows_powershell_commands_as_utf16le_base64() {
            assert_eq!(
                encode_powershell_command("Write-Output 'ok'\n"),
                "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAG8AawAnAAoA"
            );
        }

        #[test]
        fn accepts_only_powershell_progress_clixml() {
            let stderr = br#"#< CLIXML
<Objs Version="1.1.0.1"><Obj S="progress"><MS /></Obj></Objs>"#;
            assert!(is_benign_progress_clixml(stderr));
        }

        #[test]
        fn rejects_nonprogress_powershell_clixml() {
            let stderr = br#"#< CLIXML
<Objs Version="1.1.0.1"><Obj S="error"><MS /></Obj></Objs>"#;
            assert!(!is_benign_progress_clixml(stderr));
            assert!(!is_benign_progress_clixml(b"ordinary stderr"));
        }
    }
}
