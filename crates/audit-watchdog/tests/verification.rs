use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use systeme_local_audit_watchdog::{Digest, verify_files};

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, io::Error> {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "systeme-local-watchdog-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "failed to remove test directory {}: {error}",
                self.path.display()
            );
        }
    }
}

struct Fixture {
    _directory: TestDirectory,
    receipt_path: PathBuf,
    anchor_path: PathBuf,
    first_checkpoint_hmac: String,
    first_last_hmac: String,
    audit_log_id: String,
}

impl Fixture {
    fn create(advanced: bool) -> Result<Self, Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let anchor_path = directory.path.join("audit-anchor.jsonl");
        let receipt_path = directory.path.join("bootstrap-receipt.json");
        let first_checkpoint_hmac = repeated_hex('1');
        let first_last_hmac = repeated_hex('a');
        let audit_log_id = repeated_hex('b');

        let first = checkpoint(
            "11111111-1111-4111-8111-111111111111",
            10,
            &first_last_hmac,
            &repeated_hex('0'),
            &first_checkpoint_hmac,
            &audit_log_id,
        );
        let mut first_line = serde_json::to_vec(&first)?;
        first_line.push(b'\n');

        let mut anchor_bytes = first_line.clone();
        if advanced {
            let second = checkpoint(
                "22222222-2222-4222-8222-222222222222",
                11,
                &repeated_hex('c'),
                &first_checkpoint_hmac,
                &repeated_hex('2'),
                &audit_log_id,
            );
            let mut second_line = serde_json::to_vec(&second)?;
            second_line.push(b'\n');
            anchor_bytes.extend(second_line);
        }
        fs::write(&anchor_path, anchor_bytes)?;

        let prefix_hash_bytes: [u8; 32] = Sha256::digest(&first_line).into();
        let prefix_hash = Digest::from_bytes(prefix_hash_bytes).to_string();
        let canonical_anchor = fs::canonicalize(&anchor_path)?;
        let receipt = json!({
            "version": 1,
            "created_at_utc": "2026-07-16T19:31:51Z",
            "git_commit": "7bf2a55ca4435735c901e573725847cca5c86505",
            "anchor_path": canonical_anchor.to_string_lossy(),
            "records": 10,
            "last_hmac": first_last_hmac,
            "checkpoint_hmac": first_checkpoint_hmac,
            "anchor_sha256": prefix_hash,
            "storage_profile": "local-ntfs-hardened",
            "rollback_domain": "same-volume-as-audit-log"
        });
        fs::write(&receipt_path, serde_json::to_vec(&receipt)?)?;

        Ok(Self {
            _directory: directory,
            receipt_path,
            anchor_path,
            first_checkpoint_hmac,
            first_last_hmac,
            audit_log_id,
        })
    }

    fn receipt_value(&self) -> Result<Value, Box<dyn Error>> {
        Ok(serde_json::from_slice(&fs::read(&self.receipt_path)?)?)
    }

    fn write_receipt(&self, value: &Value) -> Result<(), Box<dyn Error>> {
        fs::write(&self.receipt_path, serde_json::to_vec(value)?)?;
        Ok(())
    }

    fn rewrite_bootstrap_anchor_with_crlf(&self) -> Result<(), Box<dyn Error>> {
        let bytes = fs::read(&self.anchor_path)?;
        let line_without_lf = bytes.strip_suffix(b"\n").ok_or_else(expected_failure)?;
        if line_without_lf.contains(&b'\n') {
            return Err(Box::new(io::Error::other(
                "CRLF fixture requires one checkpoint",
            )));
        }

        let mut crlf_bytes = line_without_lf.to_vec();
        crlf_bytes.extend_from_slice(b"\r\n");
        fs::write(&self.anchor_path, &crlf_bytes)?;

        let prefix_hash_bytes: [u8; 32] = Sha256::digest(&crlf_bytes).into();
        let mut receipt = self.receipt_value()?;
        receipt["anchor_sha256"] = json!(Digest::from_bytes(prefix_hash_bytes).to_string());
        self.write_receipt(&receipt)
    }

    fn append_checkpoint(
        &self,
        records: u64,
        previous: &str,
        checkpoint_hmac: &str,
    ) -> Result<(), Box<dyn Error>> {
        let value = checkpoint(
            "33333333-3333-4333-8333-333333333333",
            records,
            &repeated_hex('d'),
            previous,
            checkpoint_hmac,
            &self.audit_log_id,
        );
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        let mut existing = fs::read(&self.anchor_path)?;
        existing.extend(bytes);
        fs::write(&self.anchor_path, existing)?;
        Ok(())
    }
}

fn checkpoint(
    checkpoint_id: &str,
    records: u64,
    last_hmac: &str,
    previous_checkpoint_hmac: &str,
    checkpoint_hmac: &str,
    audit_log_id: &str,
) -> Value {
    json!({
        "version": 1,
        "checkpoint_id": checkpoint_id,
        "timestamp": "2026-07-16T19:31:51Z",
        "audit_log_id": audit_log_id,
        "records": records,
        "last_hmac": last_hmac,
        "previous_checkpoint_hmac": previous_checkpoint_hmac,
        "checkpoint_hmac": checkpoint_hmac
    })
}

fn repeated_hex(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn expected_failure() -> io::Error {
    io::Error::other("verification unexpectedly succeeded")
}

fn assert_error_contains(
    receipt_path: &Path,
    anchor_path: &Path,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let error = verify_files(receipt_path, anchor_path)
        .err()
        .ok_or_else(expected_failure)?;
    assert!(
        error.to_string().contains(expected),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn accepts_the_bootstrap_snapshot() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let report = verify_files(&fixture.receipt_path, &fixture.anchor_path)?;

    assert_eq!(report.checkpoints, 1);
    assert_eq!(report.bootstrap_records, 10);
    assert_eq!(report.current_records, 10);
    assert!(!report.advanced_since_bootstrap);
    assert_eq!(
        serde_json::to_value(report.storage_profile)?,
        json!("local-ntfs-hardened")
    );
    assert_eq!(
        serde_json::to_value(report.rollback_domain)?,
        json!("same-volume-as-audit-log")
    );
    assert!(!report.cryptographic_authentication_performed);
    Ok(())
}

#[test]
fn accepts_crlf_anchor_records_and_hashes_the_raw_prefix() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    fixture.rewrite_bootstrap_anchor_with_crlf()?;

    let report = verify_files(&fixture.receipt_path, &fixture.anchor_path)?;

    assert_eq!(report.checkpoints, 1);
    assert_eq!(report.bootstrap_records, 10);
    assert_eq!(report.current_records, 10);
    Ok(())
}

#[test]
fn accepts_valid_checkpoints_after_bootstrap() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(true)?;
    let report = verify_files(&fixture.receipt_path, &fixture.anchor_path)?;

    assert_eq!(report.checkpoints, 2);
    assert_eq!(report.current_records, 11);
    assert!(report.advanced_since_bootstrap);
    Ok(())
}

#[test]
fn rejects_unknown_receipt_fields() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let mut receipt = fixture.receipt_value()?;
    let object = receipt.as_object_mut().ok_or_else(expected_failure)?;
    object.insert("unexpected".to_owned(), json!(true));
    fixture.write_receipt(&receipt)?;

    assert_error_contains(&fixture.receipt_path, &fixture.anchor_path, "unknown field")
}

#[test]
fn rejects_a_broken_checkpoint_chain() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    fixture.append_checkpoint(11, &repeated_hex('f'), &repeated_hex('2'))?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "broken previous_checkpoint_hmac chain",
    )
}

#[test]
fn rejects_non_monotonic_record_counts() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    fixture.append_checkpoint(10, &fixture.first_checkpoint_hmac, &repeated_hex('2'))?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "record count must increase strictly",
    )
}

#[test]
fn rejects_a_modified_bootstrap_prefix() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let mut receipt = fixture.receipt_value()?;
    receipt["anchor_sha256"] = json!(repeated_hex('0'));
    fixture.write_receipt(&receipt)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "anchor_sha256 does not match",
    )
}

#[test]
fn rejects_a_receipt_for_another_anchor_path() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let other_path = fixture
        .anchor_path
        .parent()
        .ok_or_else(expected_failure)?
        .join("other-anchor.jsonl");
    fs::copy(&fixture.anchor_path, &other_path)?;

    let mut receipt = fixture.receipt_value()?;
    receipt["anchor_path"] = json!(fs::canonicalize(other_path)?.to_string_lossy());
    fixture.write_receipt(&receipt)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "does not match verified path",
    )
}

#[test]
fn rejects_an_anchor_without_a_final_newline() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let mut bytes = fs::read(&fixture.anchor_path)?;
    if bytes.pop() != Some(b'\n') {
        return Err(Box::new(expected_failure()));
    }
    fs::write(&fixture.anchor_path, bytes)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "must end with a newline",
    )
}

#[test]
fn rejects_a_non_utc_timestamp() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let mut receipt = fixture.receipt_value()?;
    receipt["created_at_utc"] = json!("2026-07-16T21:31:51+02:00");
    fixture.write_receipt(&receipt)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "created_at_utc must use UTC",
    )
}

#[test]
fn rejects_bootstrap_checkpoint_not_in_first_position() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(true)?;
    let mut receipt = fixture.receipt_value()?;
    receipt["records"] = json!(11);
    receipt["last_hmac"] = json!(repeated_hex('c'));
    receipt["checkpoint_hmac"] = json!(repeated_hex('2'));

    let anchor_bytes = fs::read(&fixture.anchor_path)?;
    let full_hash_bytes: [u8; 32] = Sha256::digest(&anchor_bytes).into();
    receipt["anchor_sha256"] = json!(Digest::from_bytes(full_hash_bytes).to_string());
    fixture.write_receipt(&receipt)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "bootstrap checkpoint must be the first",
    )
}

#[test]
fn rejects_receipt_last_hmac_mismatch() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    let mut receipt = fixture.receipt_value()?;
    receipt["last_hmac"] = json!(repeated_hex('e'));
    fixture.write_receipt(&receipt)?;

    assert_error_contains(
        &fixture.receipt_path,
        &fixture.anchor_path,
        "last_hmac does not match",
    )
}

#[test]
fn fixture_tracks_expected_first_hmac() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::create(false)?;
    assert_eq!(fixture.first_last_hmac, repeated_hex('a'));
    Ok(())
}
