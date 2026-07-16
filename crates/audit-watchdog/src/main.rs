use std::env;
use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use systeme_local_audit_watchdog::{VerificationReport, verify_project_root};

const USAGE: &str = "\
Usage:
  systeme-local-audit-watchdog verify [--project-root PATH]
  systeme-local-audit-watchdog --help

The command emits one JSON object and never reads audit HMAC keys.
";

#[derive(Debug)]
enum ParsedCommand {
    Help,
    Verify { project_root: PathBuf },
}

#[derive(Serialize)]
struct SuccessOutput<'a> {
    status: &'static str,
    report: &'a VerificationReport,
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
        Err(message) => {
            let code = emit_error(&message, 64);
            let _write_result = write_stderr(USAGE);
            code
        }
    }
}

fn parse_command() -> Result<ParsedCommand, String> {
    let mut arguments = env::args_os();
    let _program = arguments.next();

    let Some(command) = arguments.next() else {
        return Err("missing command".to_owned());
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        return Ok(ParsedCommand::Help);
    }
    if command != OsStr::new("verify") {
        return Err(format!("unknown command {}", command.to_string_lossy()));
    }

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

    Ok(ParsedCommand::Verify { project_root })
}

fn write_help() -> ExitCode {
    match write_stdout(USAGE) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => emit_error(&format!("writing help failed: {error}"), 74),
    }
}

fn emit_success(report: &VerificationReport) -> ExitCode {
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

fn emit_json<T: Serialize>(value: &T, to_stderr: bool, code: u8) -> ExitCode {
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
