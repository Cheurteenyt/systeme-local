use std::path::Path;

use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::error::VerificationError;
use crate::model::{
    BootstrapReceipt, FORMAT_VERSION, VerificationReport, VerificationScope, WindowsAclReport,
    WindowsEventWitnessReport, WindowsVerificationReport,
};

const SNAPSHOT_VERSION: u64 = 1;
const SYSTEM_SID: &str = "S-1-5-18";
const EVENT_PROVIDER: &str = "SystemeLocalAuditAnchor";
const EVENT_ID: u32 = 18_001;
const ACL_OBJECTS_VERIFIED: usize = 5;
const MAX_INSPECTED_EVENTS: u64 = 64;

const FULL_CONTROL: i64 = 2_032_127;
const DIRECTORY_RUNTIME_RIGHTS: i64 = 1_179_817;
const WRITABLE_RUNTIME_RIGHTS: i64 = 1_180_063;
const READ_ONLY_RUNTIME_RIGHTS: i64 = 1_179_785;

const INHERIT_NONE: u32 = 0;
const INHERIT_CONTAINERS_AND_OBJECTS: u32 = 3;
const PROPAGATE_NONE: u32 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum AclKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsSnapshot {
    version: u64,
    inspected_events: u64,
    acl: WindowsAclSet,
    events: Vec<WindowsEventSnapshot>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAclSet {
    directory: AclSnapshot,
    anchor: AclSnapshot,
    lock: AclSnapshot,
    receipt: AclSnapshot,
    dotenv: AclSnapshot,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclSnapshot {
    path: String,
    kind: AclKind,
    owner_sid: String,
    access_rules_protected: bool,
    rules: Vec<AclRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclRule {
    sid: String,
    rights: i64,
    access_type: String,
    inherited: bool,
    inheritance_flags: u32,
    propagation_flags: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsEventSnapshot {
    record_id: u64,
    time_created_utc: String,
    provider_name: String,
    event_id: u32,
    fields: WindowsEventFields,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsEventFields {
    path: String,
    records: u64,
    last_hmac: String,
    checkpoint_hmac: String,
    anchor_sha256: String,
    git_commit: String,
}

struct AclExpectation<'a> {
    name: &'static str,
    path: &'a Path,
    kind: AclKind,
    runtime_rights: i64,
    system_inheritance_flags: u32,
}

/// Validates one Windows metadata snapshot against a verified bootstrap witness.
///
/// # Errors
///
/// Returns [`VerificationError`] when ACLs, the runtime SID, or the Event Log
/// witness do not match the protected local bootstrap state.
pub(crate) fn validate_windows_snapshot(
    project_root: &Path,
    receipt: &BootstrapReceipt,
    core: VerificationReport,
    snapshot: &WindowsSnapshot,
) -> Result<WindowsVerificationReport, VerificationError> {
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(VerificationError::windows_witness(format!(
            "unsupported snapshot version {}",
            snapshot.version
        )));
    }
    if !(1..=MAX_INSPECTED_EVENTS).contains(&snapshot.inspected_events) {
        return Err(VerificationError::windows_witness(format!(
            "inspected_events must be between 1 and {MAX_INSPECTED_EVENTS}"
        )));
    }
    let parsed_event_count = u64::try_from(snapshot.events.len()).map_err(|_| {
        VerificationError::windows_witness("platform cannot represent parsed event count")
    })?;
    if parsed_event_count > snapshot.inspected_events {
        return Err(VerificationError::windows_witness(
            "parsed event count exceeds inspected_events",
        ));
    }

    validate_core_binding(receipt, &core)?;

    let state_directory = project_root.join(".systeme-local").join("audit-anchor");
    let anchor_path = state_directory.join("audit-anchor.jsonl");
    let lock_path = state_directory.join("audit-anchor.jsonl.lock");
    let receipt_path = state_directory.join("bootstrap-receipt.json");
    let dotenv_path = project_root.join(".env");

    let runtime_sid = validate_acl_set(
        &snapshot.acl,
        &state_directory,
        &anchor_path,
        &lock_path,
        &receipt_path,
        &dotenv_path,
    )?;

    let event = select_event(&snapshot.events, receipt)?;
    Ok(WindowsVerificationReport {
        version: FORMAT_VERSION,
        scope: VerificationScope::WindowsLocalWitnessConsistency,
        core,
        acl: WindowsAclReport {
            owner_sid: SYSTEM_SID.to_owned(),
            activation_runtime_sid: runtime_sid,
            objects_verified: ACL_OBJECTS_VERIFIED,
            dacl_protection_verified: true,
        },
        event: WindowsEventWitnessReport {
            provider_name: event.provider_name.clone(),
            event_id: event.event_id,
            record_id: event.record_id,
            time_created_utc: event.time_created_utc.clone(),
            inspected_events: snapshot.inspected_events,
        },
        lock_coordinated_snapshot: true,
        powershell_collector_used: true,
        cryptographic_authentication_performed: false,
    })
}

fn validate_core_binding(
    receipt: &BootstrapReceipt,
    core: &VerificationReport,
) -> Result<(), VerificationError> {
    if core.version != FORMAT_VERSION
        || core.scope != VerificationScope::NonSecretWitnessConsistency
        || core.storage_profile != receipt.storage_profile
        || core.rollback_domain != receipt.rollback_domain
        || core.bootstrap_records != receipt.records
        || core.bootstrap_checkpoint_hmac != receipt.checkpoint_hmac
        || core.bootstrap_prefix_sha256 != receipt.anchor_sha256
        || core.current_records < receipt.records
        || core.cryptographic_authentication_performed
    {
        return Err(VerificationError::windows_witness(
            "portable verification report is not bound to the bootstrap receipt",
        ));
    }
    Ok(())
}

fn validate_acl_set(
    acl: &WindowsAclSet,
    state_directory: &Path,
    anchor_path: &Path,
    lock_path: &Path,
    receipt_path: &Path,
    dotenv_path: &Path,
) -> Result<String, VerificationError> {
    let runtime_sid = derive_runtime_sid(&acl.directory)?;

    let expectations = [
        (
            &acl.directory,
            AclExpectation {
                name: "anchor directory",
                path: state_directory,
                kind: AclKind::Directory,
                runtime_rights: DIRECTORY_RUNTIME_RIGHTS,
                system_inheritance_flags: INHERIT_CONTAINERS_AND_OBJECTS,
            },
        ),
        (
            &acl.anchor,
            AclExpectation {
                name: "anchor file",
                path: anchor_path,
                kind: AclKind::File,
                runtime_rights: WRITABLE_RUNTIME_RIGHTS,
                system_inheritance_flags: INHERIT_NONE,
            },
        ),
        (
            &acl.lock,
            AclExpectation {
                name: "anchor lock",
                path: lock_path,
                kind: AclKind::File,
                runtime_rights: WRITABLE_RUNTIME_RIGHTS,
                system_inheritance_flags: INHERIT_NONE,
            },
        ),
        (
            &acl.receipt,
            AclExpectation {
                name: "bootstrap receipt",
                path: receipt_path,
                kind: AclKind::File,
                runtime_rights: READ_ONLY_RUNTIME_RIGHTS,
                system_inheritance_flags: INHERIT_NONE,
            },
        ),
        (
            &acl.dotenv,
            AclExpectation {
                name: ".env",
                path: dotenv_path,
                kind: AclKind::File,
                runtime_rights: WRITABLE_RUNTIME_RIGHTS,
                system_inheritance_flags: INHERIT_NONE,
            },
        ),
    ];

    for (snapshot, expectation) in expectations {
        validate_acl(snapshot, &expectation, &runtime_sid)?;
    }
    Ok(runtime_sid)
}

fn derive_runtime_sid(directory: &AclSnapshot) -> Result<String, VerificationError> {
    if directory.rules.len() != 2 {
        return Err(VerificationError::windows_witness(
            "anchor directory must contain exactly two explicit ACEs",
        ));
    }

    let mut candidates = directory.rules.iter().filter(|rule| rule.sid != SYSTEM_SID);
    let runtime_rule = candidates.next().ok_or_else(|| {
        VerificationError::windows_witness("anchor directory must identify exactly one runtime SID")
    })?;
    if candidates.next().is_some() {
        return Err(VerificationError::windows_witness(
            "anchor directory must identify exactly one runtime SID",
        ));
    }

    let runtime_sid = &runtime_rule.sid;
    validate_sid(runtime_sid)?;
    Ok(runtime_sid.clone())
}

fn validate_acl(
    snapshot: &AclSnapshot,
    expectation: &AclExpectation<'_>,
    runtime_sid: &str,
) -> Result<(), VerificationError> {
    if snapshot.kind != expectation.kind {
        return Err(VerificationError::windows_witness(format!(
            "{} has the wrong object kind",
            expectation.name
        )));
    }
    if !windows_paths_equal(&snapshot.path, &expectation.path.to_string_lossy()) {
        return Err(VerificationError::windows_witness(format!(
            "{} path does not match the project",
            expectation.name
        )));
    }
    if snapshot.owner_sid != SYSTEM_SID {
        return Err(VerificationError::windows_witness(format!(
            "{} owner must be SYSTEM",
            expectation.name
        )));
    }
    if !snapshot.access_rules_protected {
        return Err(VerificationError::windows_witness(format!(
            "{} DACL must disable inherited access rules",
            expectation.name
        )));
    }
    if snapshot.rules.len() != 2 {
        return Err(VerificationError::windows_witness(format!(
            "{} must contain exactly two explicit ACEs",
            expectation.name
        )));
    }

    let system_rule = find_rule(&snapshot.rules, SYSTEM_SID, expectation.name)?;
    validate_rule(
        system_rule,
        FULL_CONTROL,
        expectation.system_inheritance_flags,
        expectation.name,
        "SYSTEM",
    )?;

    let runtime_rule = find_rule(&snapshot.rules, runtime_sid, expectation.name)?;
    validate_rule(
        runtime_rule,
        expectation.runtime_rights,
        INHERIT_NONE,
        expectation.name,
        "runtime",
    )
}

fn find_rule<'a>(
    rules: &'a [AclRule],
    sid: &str,
    object_name: &str,
) -> Result<&'a AclRule, VerificationError> {
    let mut matches = rules.iter().filter(|rule| rule.sid == sid);
    let rule = matches.next().ok_or_else(|| {
        VerificationError::windows_witness(format!(
            "{object_name} must contain exactly one ACE for {sid}"
        ))
    })?;
    if matches.next().is_some() {
        return Err(VerificationError::windows_witness(format!(
            "{object_name} must contain exactly one ACE for {sid}"
        )));
    }
    Ok(rule)
}

fn validate_rule(
    rule: &AclRule,
    rights: i64,
    inheritance_flags: u32,
    object_name: &str,
    principal: &str,
) -> Result<(), VerificationError> {
    if rule.access_type != "Allow"
        || rule.inherited
        || rule.rights != rights
        || rule.inheritance_flags != inheritance_flags
        || rule.propagation_flags != PROPAGATE_NONE
    {
        return Err(VerificationError::windows_witness(format!(
            "{object_name} has an unexpected {principal} ACE"
        )));
    }
    Ok(())
}

fn select_event<'a>(
    events: &'a [WindowsEventSnapshot],
    receipt: &BootstrapReceipt,
) -> Result<&'a WindowsEventSnapshot, VerificationError> {
    let receipt_time = parse_utc(&receipt.created_at_utc, "receipt created_at_utc")?;
    let mut selected: Option<&WindowsEventSnapshot> = None;

    for event in events {
        if event.provider_name != EVENT_PROVIDER || event.event_id != EVENT_ID {
            return Err(VerificationError::windows_witness(
                "collector returned an event outside the required provider and ID",
            ));
        }
        if !event_fields_match(&event.fields, receipt) {
            continue;
        }

        let event_time = parse_utc(&event.time_created_utc, "event time_created_utc")?;
        if event_time < receipt_time || event.record_id == 0 {
            continue;
        }
        if selected.is_none_or(|current| event.record_id > current.record_id) {
            selected = Some(event);
        }
    }

    selected.ok_or_else(|| {
        VerificationError::windows_witness(
            "no Application/SystemeLocalAuditAnchor/18001 event matches the bootstrap receipt",
        )
    })
}

fn event_fields_match(fields: &WindowsEventFields, receipt: &BootstrapReceipt) -> bool {
    windows_paths_equal(&fields.path, &receipt.anchor_path)
        && fields.records == receipt.records
        && fields.last_hmac == receipt.last_hmac.to_string()
        && fields.checkpoint_hmac == receipt.checkpoint_hmac.to_string()
        && fields.anchor_sha256 == receipt.anchor_sha256.to_string()
        && fields.git_commit == receipt.git_commit
}

fn parse_utc(value: &str, field: &str) -> Result<OffsetDateTime, VerificationError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        VerificationError::windows_witness(format!("{field} is not RFC 3339: {error}"))
    })?;
    if parsed.offset() != UtcOffset::UTC {
        return Err(VerificationError::windows_witness(format!(
            "{field} must use UTC"
        )));
    }
    Ok(parsed)
}

fn validate_sid(value: &str) -> Result<(), VerificationError> {
    let mut parts = value.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return Err(VerificationError::windows_witness(
            "runtime SID is not canonical",
        ));
    }

    let remaining: Vec<&str> = parts.collect();
    if remaining.len() < 2
        || remaining
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(VerificationError::windows_witness(
            "runtime SID is not canonical",
        ));
    }
    Ok(())
}

fn windows_paths_equal(left: &str, right: &str) -> bool {
    normalize_windows_path(left) == normalize_windows_path(right)
}

fn normalize_windows_path(value: &str) -> String {
    let replaced = value.replace('\\', "/");
    let without_extended_prefix = if let Some(rest) = replaced.strip_prefix("//?/UNC/") {
        format!("//{rest}")
    } else if let Some(rest) = replaced.strip_prefix("//?/") {
        rest.to_owned()
    } else {
        replaced
    };

    let mut normalized = without_extended_prefix.trim_end_matches('/').to_owned();
    if normalized.len() == 2 && normalized.as_bytes()[1] == b':' {
        normalized.push('/');
    }
    normalized.make_ascii_lowercase();
    normalized
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::path::Path;

    use crate::Digest;
    use crate::model::{
        BootstrapReceipt, RollbackDomain, StorageProfile, VerificationReport, VerificationScope,
    };

    use super::{
        AclKind, AclRule, AclSnapshot, WindowsAclSet, WindowsEventFields, WindowsEventSnapshot,
        WindowsSnapshot, validate_windows_snapshot,
    };

    const ROOT: &str = "D:/systeme-local-agent-gateway-github";
    const SYSTEM_SID: &str = "S-1-5-18";
    const RUNTIME_SID: &str = "S-1-5-21-1616043031-1921332813-1227433008-1001";

    fn digest(character: char) -> Result<Digest, Box<dyn Error>> {
        Ok(Digest::parse(
            &std::iter::repeat_n(character, 64).collect::<String>(),
        )?)
    }

    fn valid_receipt() -> Result<BootstrapReceipt, Box<dyn Error>> {
        Ok(BootstrapReceipt {
            version: 1,
            created_at_utc: "2026-07-16T19:31:51+00:00".to_owned(),
            git_commit: "aef4eee017261978449497ce08f0213f91e15e66".to_owned(),
            anchor_path: format!("{ROOT}/.systeme-local/audit-anchor/audit-anchor.jsonl"),
            records: 10,
            last_hmac: digest('a')?,
            checkpoint_hmac: digest('b')?,
            anchor_sha256: digest('c')?,
            storage_profile: StorageProfile::LocalNtfsHardened,
            rollback_domain: RollbackDomain::SameVolumeAsAuditLog,
        })
    }

    fn valid_core(receipt: &BootstrapReceipt) -> VerificationReport {
        VerificationReport {
            version: 1,
            scope: VerificationScope::NonSecretWitnessConsistency,
            storage_profile: receipt.storage_profile,
            rollback_domain: receipt.rollback_domain,
            checkpoints: 1,
            bootstrap_records: receipt.records,
            current_records: receipt.records,
            current_last_hmac: receipt.last_hmac,
            bootstrap_checkpoint_hmac: receipt.checkpoint_hmac,
            bootstrap_prefix_sha256: receipt.anchor_sha256,
            advanced_since_bootstrap: false,
            cryptographic_authentication_performed: false,
        }
    }

    fn rule(sid: &str, rights: i64, inheritance_flags: u32) -> AclRule {
        AclRule {
            sid: sid.to_owned(),
            rights,
            access_type: "Allow".to_owned(),
            inherited: false,
            inheritance_flags,
            propagation_flags: 0,
        }
    }

    fn acl(
        path: &str,
        kind: AclKind,
        runtime_rights: i64,
        system_inheritance_flags: u32,
    ) -> AclSnapshot {
        AclSnapshot {
            path: path.to_owned(),
            kind,
            owner_sid: SYSTEM_SID.to_owned(),
            access_rules_protected: true,
            rules: vec![
                rule(SYSTEM_SID, 2_032_127, system_inheritance_flags),
                rule(RUNTIME_SID, runtime_rights, 0),
            ],
        }
    }

    fn valid_snapshot(receipt: &BootstrapReceipt) -> WindowsSnapshot {
        let state = format!("{ROOT}/.systeme-local/audit-anchor");
        WindowsSnapshot {
            version: 1,
            inspected_events: 1,
            acl: WindowsAclSet {
                directory: acl(&state, AclKind::Directory, 1_179_817, 3),
                anchor: acl(
                    &format!("{state}/audit-anchor.jsonl"),
                    AclKind::File,
                    1_180_063,
                    0,
                ),
                lock: acl(
                    &format!("{state}/audit-anchor.jsonl.lock"),
                    AclKind::File,
                    1_180_063,
                    0,
                ),
                receipt: acl(
                    &format!("{state}/bootstrap-receipt.json"),
                    AclKind::File,
                    1_179_785,
                    0,
                ),
                dotenv: acl(&format!("{ROOT}/.env"), AclKind::File, 1_180_063, 0),
            },
            events: vec![WindowsEventSnapshot {
                record_id: 4_900,
                time_created_utc: "2026-07-16T19:31:51.7135761Z".to_owned(),
                provider_name: "SystemeLocalAuditAnchor".to_owned(),
                event_id: 18_001,
                fields: WindowsEventFields {
                    path: receipt.anchor_path.clone(),
                    records: receipt.records,
                    last_hmac: receipt.last_hmac.to_string(),
                    checkpoint_hmac: receipt.checkpoint_hmac.to_string(),
                    anchor_sha256: receipt.anchor_sha256.to_string(),
                    git_commit: receipt.git_commit.clone(),
                },
            }],
        }
    }

    fn expected_failure() -> io::Error {
        io::Error::other("Windows witness verification unexpectedly succeeded")
    }

    fn assert_rejected(
        receipt: &BootstrapReceipt,
        snapshot: &WindowsSnapshot,
        expected: &str,
    ) -> Result<(), Box<dyn Error>> {
        let error =
            validate_windows_snapshot(Path::new(ROOT), receipt, valid_core(receipt), snapshot)
                .err()
                .ok_or_else(expected_failure)?;
        assert!(
            error.to_string().contains(expected),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn accepts_the_captured_windows_contract() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let report = validate_windows_snapshot(
            Path::new(ROOT),
            &receipt,
            valid_core(&receipt),
            &valid_snapshot(&receipt),
        )?;

        assert_eq!(report.acl.activation_runtime_sid, RUNTIME_SID);
        assert_eq!(report.acl.objects_verified, 5);
        assert_eq!(report.event.record_id, 4_900);
        assert!(report.lock_coordinated_snapshot);
        assert!(report.powershell_collector_used);
        assert!(!report.cryptographic_authentication_performed);
        Ok(())
    }

    #[test]
    fn accepts_extended_length_and_case_insensitive_paths() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.events[0].fields.path =
            r"\\?\d:\SYSTEME-LOCAL-AGENT-GATEWAY-GITHUB\.systeme-local\audit-anchor\audit-anchor.jsonl"
                .to_owned();

        validate_windows_snapshot(Path::new(ROOT), &receipt, valid_core(&receipt), &snapshot)?;
        Ok(())
    }

    #[test]
    fn rejects_an_unprotected_dacl() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.acl.anchor.access_rules_protected = false;
        assert_rejected(&receipt, &snapshot, "DACL must disable inherited")
    }

    #[test]
    fn rejects_an_extra_ace() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot
            .acl
            .lock
            .rules
            .push(rule("S-1-5-32-544", 2_032_127, 0));
        assert_rejected(&receipt, &snapshot, "exactly two explicit ACEs")
    }

    #[test]
    fn rejects_wrong_runtime_rights() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.acl.receipt.rules[1].rights = 1_180_063;
        assert_rejected(&receipt, &snapshot, "unexpected runtime ACE")
    }

    #[test]
    fn rejects_a_runtime_sid_mismatch() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.acl.dotenv.rules[1].sid = "S-1-5-21-9-9-9-1002".to_owned();
        assert_rejected(&receipt, &snapshot, "exactly one ACE")
    }

    #[test]
    fn rejects_a_missing_matching_event() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.events[0].fields.records += 1;
        assert_rejected(&receipt, &snapshot, "no Application")
    }

    #[test]
    fn rejects_an_event_older_than_the_receipt() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.events[0].time_created_utc = "2026-07-16T19:31:50Z".to_owned();
        assert_rejected(&receipt, &snapshot, "no Application")
    }

    #[test]
    fn rejects_an_event_from_another_provider() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.events[0].provider_name = "OtherProvider".to_owned();
        assert_rejected(&receipt, &snapshot, "outside the required provider")
    }

    #[test]
    fn rejects_a_noncanonical_runtime_sid() -> Result<(), Box<dyn Error>> {
        let receipt = valid_receipt()?;
        let mut snapshot = valid_snapshot(&receipt);
        snapshot.acl.directory.rules[1].sid = "runtime-user".to_owned();
        assert_rejected(&receipt, &snapshot, "runtime SID is not canonical")
    }
}
