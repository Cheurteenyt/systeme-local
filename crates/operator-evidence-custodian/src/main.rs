use std::io::{self, Read, Write};
use std::process::ExitCode;
use systeme_local_operator_evidence_custodian::{MAX_INPUT_BYTES, process_input_bytes};

const MAX_INPUT_BYTES_U64: u64 = 8_192;

fn run() -> io::Result<ExitCode> {
    let mut input = Vec::with_capacity(MAX_INPUT_BYTES + 1);
    io::stdin()
        .lock()
        .take(MAX_INPUT_BYTES_U64 + 1)
        .read_to_end(&mut input)?;

    let processed = process_input_bytes(&input);
    io::stdout().lock().write_all(processed.stdout.as_bytes())?;
    Ok(ExitCode::from(processed.exit_code))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(_) => ExitCode::from(3),
    }
}
