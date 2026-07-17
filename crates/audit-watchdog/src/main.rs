use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use systeme_local_audit_watchdog::{verify_project_root, verify_windows_project_root};

const USAGE: &str = "\
Usage:
  systeme-local-audit-watchdog verify [--project-root PATH]
  systeme-local-audit-watchdog verify-windows [--project-root PATH]
  systeme-local-audit-watchdog --help

Both commands emit one JSON object and never read audit HMAC keys.
The Windows command also validates hardened ACLs and the bootstrap Event Log witness.
";

#[derive(Debug, Eq, PartialEq)]
enum ParsedCommand {
    Help,
    Verify { project_root: PathBuf },
    VerifyWindows { project_root: PathBuf },
}

#[derive(Serialize)]
struct SuccessOutput<'a, T>
where
    T: Serialize,
{
    status: &'static str,
    report: &'a T,
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    status: &'static str,
    error: &'a str,
}

fn main() -> ExitCode {
    match parse_command() {
        Ok(ParsedCommand::Help) => write_help(),
        Ok(ParsedCommand::Verify { project_root }) => match verify_project_root(&project_root) {
            Ok(report) => emit_success(&report),
            Err(error) => emit_error(&error.to_string(), 1),
        },
        Ok(ParsedCommand::VerifyWindows { project_root }) => {
            match verify_windows_project_root(&project_root) {
                Ok(report) => emit_success(&report),
                Err(error) => emit_error(&error.to_string(), 1),
            }
        }
        Err(message) => {
            let code = emit_error(&message, 64);
            let _write_result = write_stderr(USAGE);
            code
        }
    }
}

fn parse_command() -> Result<ParsedCommand, String> {
    parse_arguments(env::args_os().skip(1))
}

fn parse_arguments<I>(arguments: I) -> Result<ParsedCommand, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        return Err("missing command".to_owned());
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        return Ok(ParsedCommand::Help);
    }

    let windows = if command == OsStr::new("verify") {
        false
    } else if command == OsStr::new("verify-windows") {
        true
    } else {
        return Err(format!("unknown command {}", command.to_string_lossy()));
    };

    parse_project_root(arguments, windows)
}

fn parse_project_root<I>(mut arguments: I, windows: bool) -> Result<ParsedCommand, String>
where
    I: Iterator<Item = OsString>,
{
    let mut project_root = PathBuf::from(".");
    let mut project_root_seen = false;

    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("--help") || argument == OsStr::new("-h") {
            return Ok(ParsedCommand::Help);
        }
        if argument != OsStr::new("--project-root") {
            return Err(format!("unknown argument {}", argument.to_string_lossy()));
        }
        if project_root_seen {
            return Err("--project-root may be supplied only once".to_owned());
        }
        let Some(value) = arguments.next() else {
            return Err("--project-root requires a path".to_owned());
        };
        project_root = PathBuf::from(value);
        project_root_seen = true;
    }

    if windows {
        Ok(ParsedCommand::VerifyWindows { project_root })
    } else {
        Ok(ParsedCommand::Verify { project_root })
    }
}

fn write_help() -> ExitCode {
    match write_stdout(USAGE) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => emit_error(&format!("writing help failed: {error}"), 74),
    }
}

fn emit_success<T>(report: &T) -> ExitCode
where
    T: Serialize,
{
    let output = SuccessOutput {
        status: "valid",
        report,
    };
    emit_json(&output, false, 0)
}

fn emit_error(message: &str, code: u8) -> ExitCode {
    let output = ErrorOutput {
        status: "error",
        error: message,
    };
    emit_json(&output, true, code)
}

fn emit_json<T>(value: &T, to_stderr: bool, code: u8) -> ExitCode
where
    T: Serialize,
{
    let encoded = match serde_json::to_string(value) {
        Ok(encoded) => encoded,
        Err(error) => {
            let _write_result = write_stderr(&format!(
                "{{\"status\":\"error\",\"error\":\"JSON encoding failed: {error}\"}}\n"
            ));
            return ExitCode::from(74);
        }
    };

    let result = if to_stderr {
        write_stderr(&format!("{encoded}\n"))
    } else {
        write_stdout(&format!("{encoded}\n"))
    };
    match result {
        Ok(()) => ExitCode::from(code),
        Err(_) => ExitCode::from(74),
    }
}

fn write_stdout(value: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(value.as_bytes())?;
    handle.flush()
}

fn write_stderr(value: &str) -> io::Result<()> {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    handle.write_all(value.as_bytes())?;
    handle.flush()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{ParsedCommand, parse_arguments};

    #[test]
    fn parses_portable_verification() {
        let parsed = parse_arguments([OsString::from("verify")]);
        assert_eq!(
            parsed,
            Ok(ParsedCommand::Verify {
                project_root: PathBuf::from("."),
            })
        );
    }

    #[test]
    fn parses_windows_verification_with_project_root() {
        let parsed = parse_arguments([
            OsString::from("verify-windows"),
            OsString::from("--project-root"),
            OsString::from(r"D:\systeme-local"),
        ]);
        assert_eq!(
            parsed,
            Ok(ParsedCommand::VerifyWindows {
                project_root: PathBuf::from(r"D:\systeme-local"),
            })
        );
    }

    #[test]
    fn rejects_duplicate_project_root() {
        let parsed = parse_arguments([
            OsString::from("verify"),
            OsString::from("--project-root"),
            OsString::from("."),
            OsString::from("--project-root"),
            OsString::from("."),
        ]);
        assert_eq!(
            parsed,
            Err("--project-root may be supplied only once".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_commands() {
        let parsed = parse_arguments([OsString::from("unknown")]);
        assert_eq!(parsed, Err("unknown command unknown".to_owned()));
    }
}
