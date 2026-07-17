use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::Digest;
use crate::error::VerificationError;
use crate::model::{
    AnchorCheckpoint, BootstrapReceipt, FORMAT_VERSION, VerificationReport, VerificationScope,
};

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_ANCHOR_BYTES: u64 = 64 * 1024 * 1024;
const GIT_COMMIT_HEX_LENGTH: usize = 40;
const UUID_TEXT_LENGTH: usize = 36;

struct AnchorScan {
    prefix_hasher: Sha256,
    previous_checkpoint_hmac: Digest,
    previous_records: Option<u64>,
    previous_timestamp: Option<OffsetDateTime>,
    audit_log_id: Option<Digest>,
    checkpoint_ids: HashSet<String>,
    checkpoint_hmacs: HashSet<Digest>,
    bootstrap_prefix_sha256: Option<Digest>,
    bootstrap_checkpoint_seen: bool,
    current_records: u64,
    current_last_hmac: Digest,
    checkpoints: usize,
}

impl AnchorScan {
    fn new() -> Self {
        Self {
            prefix_hasher: Sha256::new(),
            previous_checkpoint_hmac: Digest::ZERO,
            previous_records: None,
            previous_timestamp: None,
            audit_log_id: None,
            checkpoint_ids: HashSet::new(),
            checkpoint_hmacs: HashSet::new(),
            bootstrap_prefix_sha256: None,
            bootstrap_checkpoint_seen: false,
            current_records: 0,
            current_last_hmac: Digest::ZERO,
            checkpoints: 0,
        }
    }

    fn process(
        &mut self,
        checkpoint: &AnchorCheckpoint,
        line: usize,
        raw_line: &[u8],
        receipt: &BootstrapReceipt,
    ) -> Result<(), VerificationError> {
        self.prefix_hasher.update(raw_line);
        let timestamp = self.validate_checkpoint(checkpoint, line)?;

        if !self.checkpoint_ids.insert(checkpoint.checkpoint_id.clone()) {
            return Err(VerificationError::checkpoint(
                line,
                "duplicate checkpoint_id",
            ));
        }
        if !self.checkpoint_hmacs.insert(checkpoint.checkpoint_hmac) {
            return Err(VerificationError::checkpoint(
                line,
                "duplicate checkpoint_hmac",
            ));
        }

        self.capture_bootstrap(checkpoint, line, receipt)?;

        if self.audit_log_id.is_none() {
            self.audit_log_id = Some(checkpoint.audit_log_id);
        }
        self.previous_checkpoint_hmac = checkpoint.checkpoint_hmac;
        self.previous_records = Some(checkpoint.records);
        self.previous_timestamp = Some(timestamp);
        self.current_records = checkpoint.records;
        self.current_last_hmac = checkpoint.last_hmac;
        self.checkpoints += 1;
        Ok(())
    }

    fn validate_checkpoint(
        &self,
        checkpoint: &AnchorCheckpoint,
        line: usize,
    ) -> Result<OffsetDateTime, VerificationError> {
        if checkpoint.version != FORMAT_VERSION {
            return Err(VerificationError::checkpoint(
                line,
                format!("unsupported version {}", checkpoint.version),
            ));
        }
        validate_uuid_v4(&checkpoint.checkpoint_id)
            .map_err(|message| VerificationError::checkpoint(line, message))?;
        let timestamp = parse_utc_timestamp(&checkpoint.timestamp, "timestamp")
            .map_err(|message| VerificationError::checkpoint(line, message))?;

        if checkpoint.previous_checkpoint_hmac != self.previous_checkpoint_hmac {
            return Err(VerificationError::checkpoint(
                line,
                "broken previous_checkpoint_hmac chain",
            ));
        }
        if self
            .previous_records
            .is_some_and(|previous| checkpoint.records <= previous)
        {
            return Err(VerificationError::checkpoint(
                line,
                "record count must increase strictly",
            ));
        }
        if self
            .previous_timestamp
            .is_some_and(|previous| timestamp < previous)
        {
            return Err(VerificationError::checkpoint(
                line,
                "checkpoint timestamps must not move backwards",
            ));
        }
        if checkpoint.records == 0 && checkpoint.last_hmac != Digest::ZERO {
            return Err(VerificationError::checkpoint(
                line,
                "zero-record checkpoint must use the zero audit HMAC",
            ));
        }
        if self
            .audit_log_id
            .is_some_and(|audit_log_id| checkpoint.audit_log_id != audit_log_id)
        {
            return Err(VerificationError::checkpoint(
                line,
                "audit_log_id changed within the anchor",
            ));
        }
        Ok(timestamp)
    }

    fn capture_bootstrap(
        &mut self,
        checkpoint: &AnchorCheckpoint,
        line: usize,
        receipt: &BootstrapReceipt,
    ) -> Result<(), VerificationError> {
        if checkpoint.checkpoint_hmac != receipt.checkpoint_hmac {
            return Ok(());
        }
        if self.bootstrap_checkpoint_seen {
            return Err(VerificationError::receipt(
                "checkpoint_hmac occurs more than once",
            ));
        }
        if line != 1 {
            return Err(VerificationError::receipt(
                "bootstrap checkpoint must be the first anchor record",
            ));
        }
        if checkpoint.records != receipt.records {
            return Err(VerificationError::receipt(
                "record count does not match the bootstrap checkpoint",
            ));
        }
        if checkpoint.last_hmac != receipt.last_hmac {
            return Err(VerificationError::receipt(
                "last_hmac does not match the bootstrap checkpoint",
            ));
        }

        let prefix_bytes: [u8; 32] = self.prefix_hasher.clone().finalize().into();
        self.bootstrap_prefix_sha256 = Some(Digest::from_bytes(prefix_bytes));
        self.bootstrap_checkpoint_seen = true;
        Ok(())
    }

    fn finish(self, receipt: &BootstrapReceipt) -> Result<VerificationReport, VerificationError> {
        let bootstrap_prefix_sha256 = self.bootstrap_prefix_sha256.ok_or_else(|| {
            VerificationError::receipt("referenced bootstrap checkpoint is absent")
        })?;
        if bootstrap_prefix_sha256 != receipt.anchor_sha256 {
            return Err(VerificationError::receipt(
                "anchor_sha256 does not match the exact bootstrap prefix",
            ));
        }
        if self.current_records < receipt.records {
            return Err(VerificationError::receipt(
                "current anchor record count is behind bootstrap",
            ));
        }

        Ok(VerificationReport {
            version: FORMAT_VERSION,
            scope: VerificationScope::NonSecretWitnessConsistency,
            storage_profile: receipt.storage_profile,
            rollback_domain: receipt.rollback_domain,
            checkpoints: self.checkpoints,
            bootstrap_records: receipt.records,
            current_records: self.current_records,
            current_last_hmac: self.current_last_hmac,
            bootstrap_checkpoint_hmac: receipt.checkpoint_hmac,
            bootstrap_prefix_sha256,
            advanced_since_bootstrap: self.current_records > receipt.records,
            cryptographic_authentication_performed: false,
        })
    }
}

pub(crate) struct VerifiedProjectWitness {
    pub report: VerificationReport,
    pub receipt: BootstrapReceipt,
}

/// Verifies the conventional watchdog files beneath one project root.
///
/// # Errors
///
/// Returns [`VerificationError`] when either witness file is unavailable,
/// unsafe, malformed, inconsistent, or outside the accepted resource bounds.
pub fn verify_project_root(project_root: &Path) -> Result<VerificationReport, VerificationError> {
    let VerifiedProjectWitness { report, receipt: _ } =
        verify_project_root_with_receipt(project_root)?;
    Ok(report)
}

pub(crate) fn verify_project_root_with_receipt(
    project_root: &Path,
) -> Result<VerifiedProjectWitness, VerificationError> {
    let state_directory = project_root.join(".systeme-local").join("audit-anchor");
    verify_files_with_receipt(
        &state_directory.join("bootstrap-receipt.json"),
        &state_directory.join("audit-anchor.jsonl"),
    )
}

/// Verifies an explicit receipt and anchor file.
///
/// # Errors
///
/// Returns [`VerificationError`] when either witness file is unavailable,
/// unsafe, malformed, inconsistent, or outside the accepted resource bounds.
pub fn verify_files(
    receipt_path: &Path,
    anchor_path: &Path,
) -> Result<VerificationReport, VerificationError> {
    let VerifiedProjectWitness { report, receipt: _ } =
        verify_files_with_receipt(receipt_path, anchor_path)?;
    Ok(report)
}

fn verify_files_with_receipt(
    receipt_path: &Path,
    anchor_path: &Path,
) -> Result<VerifiedProjectWitness, VerificationError> {
    let receipt = read_receipt(receipt_path)?;
    validate_receipt(&receipt)?;
    validate_anchor_path(&receipt, anchor_path)?;

    let anchor_bytes = read_limited(anchor_path, MAX_ANCHOR_BYTES)?;
    let report = scan_anchor(anchor_path, &anchor_bytes, &receipt)?;
    Ok(VerifiedProjectWitness { report, receipt })
}

fn read_receipt(path: &Path) -> Result<BootstrapReceipt, VerificationError> {
    let bytes = read_limited(path, MAX_RECEIPT_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| VerificationError::Json {
        path: path.to_path_buf(),
        line: None,
        message: error.to_string(),
    })
}

fn validate_anchor_path(
    receipt: &BootstrapReceipt,
    anchor_path: &Path,
) -> Result<(), VerificationError> {
    let recorded_path = PathBuf::from(&receipt.anchor_path);
    if !recorded_path.is_absolute() {
        return Err(VerificationError::receipt("anchor_path must be absolute"));
    }

    ensure_regular_file(anchor_path)?;
    ensure_regular_file(&recorded_path)?;

    let actual = fs::canonicalize(anchor_path)
        .map_err(|error| VerificationError::io("canonicalizing anchor", anchor_path, error))?;
    let recorded = fs::canonicalize(&recorded_path).map_err(|error| {
        VerificationError::io("canonicalizing receipt anchor path", &recorded_path, error)
    })?;
    if !paths_equal(&recorded, &actual) {
        return Err(VerificationError::AnchorPath { recorded, actual });
    }
    Ok(())
}

fn scan_anchor(
    anchor_path: &Path,
    anchor_bytes: &[u8],
    receipt: &BootstrapReceipt,
) -> Result<VerificationReport, VerificationError> {
    if anchor_bytes.is_empty() {
        return Err(VerificationError::receipt("anchor file is empty"));
    }
    if !anchor_bytes.ends_with(b"\n") {
        return Err(VerificationError::receipt(
            "anchor file must end with a newline",
        ));
    }

    let mut scan = AnchorScan::new();
    for (index, raw_line) in anchor_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
    {
        let line = index + 1;
        let line_without_lf = &raw_line[..raw_line.len() - 1];
        let payload = line_without_lf
            .strip_suffix(b"\r")
            .unwrap_or(line_without_lf);
        if payload.is_empty() {
            return Err(VerificationError::checkpoint(
                line,
                "blank checkpoints are forbidden",
            ));
        }

        let checkpoint: AnchorCheckpoint =
            serde_json::from_slice(payload).map_err(|error| VerificationError::Json {
                path: anchor_path.to_path_buf(),
                line: Some(line),
                message: error.to_string(),
            })?;
        scan.process(&checkpoint, line, raw_line, receipt)?;
    }
    scan.finish(receipt)
}

fn validate_receipt(receipt: &BootstrapReceipt) -> Result<(), VerificationError> {
    if receipt.version != FORMAT_VERSION {
        return Err(VerificationError::receipt(format!(
            "unsupported version {}",
            receipt.version
        )));
    }
    parse_utc_timestamp(&receipt.created_at_utc, "created_at_utc")
        .map_err(VerificationError::receipt)?;
    validate_lower_hex(&receipt.git_commit, GIT_COMMIT_HEX_LENGTH, "git_commit")
        .map_err(VerificationError::receipt)?;
    Ok(())
}

fn parse_utc_timestamp(value: &str, field: &str) -> Result<OffsetDateTime, String> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| format!("{field} is not RFC 3339: {error}"))?;
    if parsed.offset() != UtcOffset::UTC {
        return Err(format!("{field} must use UTC"));
    }
    Ok(parsed)
}

fn validate_lower_hex(value: &str, length: usize, field: &str) -> Result<(), String> {
    if value.len() != length {
        return Err(format!("{field} must contain exactly {length} characters"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be lowercase hexadecimal"));
    }
    Ok(())
}

fn validate_uuid_v4(value: &str) -> Result<(), String> {
    if value.len() != UUID_TEXT_LENGTH {
        return Err("checkpoint_id must use canonical UUIDv4 text".to_owned());
    }

    let encoded = value.as_bytes();
    for (index, byte) in encoded.iter().copied().enumerate() {
        let is_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if is_hyphen {
            if byte != b'-' {
                return Err("checkpoint_id must use canonical UUIDv4 text".to_owned());
            }
        } else if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
            return Err("checkpoint_id must use lowercase canonical UUIDv4 text".to_owned());
        }
    }
    if encoded[14] != b'4' || !matches!(encoded[19], b'8'..=b'b') {
        return Err("checkpoint_id must identify a variant-1 UUIDv4".to_owned());
    }
    Ok(())
}

pub(crate) fn ensure_regular_file(path: &Path) -> Result<(), VerificationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| VerificationError::io("reading metadata", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(VerificationError::UnsafeFileType {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, VerificationError> {
    ensure_regular_file(path)?;

    let file =
        File::open(path).map_err(|error| VerificationError::io("opening file", path, error))?;
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| VerificationError::receipt("verification size limit overflow"))?;
    let mut reader = file.take(read_limit);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| VerificationError::io("reading file", path, error))?;

    let too_large_threshold = usize::try_from(read_limit)
        .map_err(|_| VerificationError::receipt("platform cannot represent size limit"))?;
    if bytes.len() >= too_large_threshold {
        return Err(VerificationError::SizeLimit {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

#[cfg(windows)]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

#[cfg(not(windows))]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}
