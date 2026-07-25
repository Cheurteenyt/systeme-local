use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use systeme_local_operator_evidence_custodian::{
    ControlledStagingRoot, CustodySession, DispositionError, DispositionProgress,
    DispositionReason, LogicalDispositionReceipt, PreparedDisposition, RetentionDecision,
    SanitizerProfileId, SessionAction, SessionId, SessionState, SourceName, SourceReadLimit,
    StagingParent, commit_controlled_synthetic_source, prepare_sanitized_disposition,
    prepare_terminal_disposition, sanitize_controlled_synthetic_source,
};

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
const OTHER_SESSION: &str = "ses_fedcba9876543210fedcba9876543210";
const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";
const JUSTIFICATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UI_EXPORT: &[u8] = b"access_control=restricted\naction_review=approved\napp_state=draft\nauthentication=available\ntool_scan=passed\ntransport=available\n";

struct TempParent {
    path: PathBuf,
}

impl TempParent {
    fn new() -> io::Result<Self> {
        let parent = std::env::temp_dir();

        for _ in 0..100 {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "systeme-local-logical-disposition-{}-{nonce}",
                std::process::id()
            ));

            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to allocate logical-disposition test parent",
        ))
    }

    fn staging_path(&self, session: &str) -> PathBuf {
        self.path
            .join(format!("stg_{}", session.trim_start_matches("ses_")))
    }
}

impl Drop for TempParent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn source_name() -> Result<SourceName, Box<dyn Error>> {
    Ok(SourceName::from_str(SOURCE)?)
}

fn created_session() -> Result<CustodySession, Box<dyn Error>> {
    Ok(CustodySession::new(SessionId::from_str(SESSION)?))
}

fn write_source(temp: &TempParent, bytes: &[u8]) -> io::Result<()> {
    fs::write(temp.staging_path(SESSION).join(SOURCE), bytes)
}

struct CompletedDispositionFixture {
    session: CustodySession,
    prepared: PreparedDisposition,
    receipt: LogicalDispositionReceipt,
}

fn completed_immediate_disposition() -> Result<CompletedDispositionFixture, Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session()?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, UI_EXPORT)?;
    session.apply(SessionAction::BeginCollection)?;
    let source_commitment = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;
    let sanitization = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &source_commitment,
        SanitizerProfileId::UiExportV1,
    )?;
    session.apply(SessionAction::Seal)?;

    let decision = RetentionDecision::dispose_immediately(JUSTIFICATION, 1_000)?;
    let mut prepared = prepare_sanitized_disposition(
        &parent,
        &session,
        root,
        lease,
        source_name()?,
        source_commitment,
        sanitization,
        decision,
    )?;
    let receipt = prepared
        .dispose(&mut session)?
        .ok_or_else(|| io::Error::other("disposition did not complete"))?;

    Ok(CompletedDispositionFixture {
        session,
        prepared,
        receipt,
    })
}

#[test]
fn sealed_artifact_is_disposed_and_namespace_is_absent() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session()?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, UI_EXPORT)?;
    session.apply(SessionAction::BeginCollection)?;
    let source_commitment = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;
    let sanitization = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &source_commitment,
        SanitizerProfileId::UiExportV1,
    )?;
    session.apply(SessionAction::Seal)?;

    let decision = RetentionDecision::dispose_immediately(JUSTIFICATION, 1_000)?;
    let mut prepared = prepare_sanitized_disposition(
        &parent,
        &session,
        root,
        lease,
        source_name()?,
        source_commitment,
        sanitization,
        decision,
    )?;
    let receipt = prepared
        .dispose(&mut session)?
        .ok_or_else(|| io::Error::other("disposition did not complete"))?;

    assert_eq!(prepared.progress(), DispositionProgress::Complete);
    assert_eq!(session.state(), SessionState::Disposed);
    assert_eq!(receipt.prior_state(), SessionState::Sealed);
    assert_eq!(receipt.resulting_state(), SessionState::Disposed);
    assert_eq!(receipt.disposition_reason(), DispositionReason::Completed);
    assert!(receipt.raw_source_absent());
    assert!(receipt.lease_absent());
    assert!(receipt.staging_root_absent());
    assert!(receipt.sanitized_artifact_overwrite_attempted());
    assert_eq!(receipt.deadline_met(), None);
    assert!(!temp.staging_path(SESSION).exists());
    Ok(())
}

#[test]
fn completed_disposition_is_idempotent_for_exact_session_revision() -> Result<(), Box<dyn Error>> {
    let mut fixture = completed_immediate_disposition()?;
    let retried = fixture
        .prepared
        .dispose(&mut fixture.session)?
        .ok_or_else(|| io::Error::other("cached disposition receipt was not returned"))?;

    assert_eq!(fixture.session.state(), SessionState::Disposed);
    assert_eq!(fixture.session.revision(), fixture.receipt.revision());
    assert_eq!(retried, fixture.receipt);
    Ok(())
}

#[test]
fn completed_disposition_rejects_different_session() -> Result<(), Box<dyn Error>> {
    let mut fixture = completed_immediate_disposition()?;
    let mut unrelated = CustodySession::new(SessionId::from_str(OTHER_SESSION)?);

    assert_eq!(
        fixture.prepared.dispose(&mut unrelated),
        Err(DispositionError::SessionMismatch)
    );
    assert_eq!(fixture.session.state(), SessionState::Disposed);
    Ok(())
}

#[test]
fn completed_disposition_rejects_fresh_same_id_session() -> Result<(), Box<dyn Error>> {
    let mut fixture = completed_immediate_disposition()?;
    let mut fresh = created_session()?;

    assert_eq!(
        fixture.prepared.dispose(&mut fresh),
        Err(DispositionError::InvalidSessionState)
    );
    assert_eq!(fresh.state(), SessionState::Created);
    assert_eq!(fresh.revision(), 0);
    Ok(())
}

#[test]
fn cached_receipt_requires_disposed_state_and_revision() -> Result<(), Box<dyn Error>> {
    let mut fixture = completed_immediate_disposition()?;
    let mut replayed = created_session()?;
    replayed.apply(SessionAction::BeginCollection)?;
    replayed.apply(SessionAction::Seal)?;
    replayed.apply(SessionAction::Retain)?;
    replayed.apply(SessionAction::Dispose)?;

    assert_eq!(replayed.state(), SessionState::Disposed);
    assert_ne!(replayed.revision(), fixture.receipt.revision());
    assert_eq!(
        fixture.prepared.dispose(&mut replayed),
        Err(DispositionError::InvalidSessionState)
    );
    Ok(())
}

#[test]
fn retained_artifact_disposes_even_after_deadline() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session()?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, UI_EXPORT)?;
    session.apply(SessionAction::BeginCollection)?;
    let source_commitment = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;
    let sanitization = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &source_commitment,
        SanitizerProfileId::UiExportV1,
    )?;
    session.apply(SessionAction::Seal)?;

    let decision = RetentionDecision::retain_until(JUSTIFICATION, 1_000, 1_900)?;
    let mut prepared = prepare_sanitized_disposition(
        &parent,
        &session,
        root,
        lease,
        source_name()?,
        source_commitment,
        sanitization,
        decision,
    )?;
    let retained = prepared
        .retain(&mut session)?
        .ok_or_else(|| io::Error::other("retention did not complete"))?;

    assert_eq!(session.state(), SessionState::Retained);
    assert!(!temp.staging_path(SESSION).exists());
    assert_eq!(retained.dispose_by_unix_seconds(), 1_900);

    let mut disposition = retained.prepare_disposition(1_901);
    let receipt = disposition
        .dispose(&mut session)?
        .ok_or_else(|| io::Error::other("retained disposition did not complete"))?;

    assert_eq!(session.state(), SessionState::Disposed);
    assert_eq!(
        receipt.disposition_reason(),
        DispositionReason::RetentionReleased
    );
    assert_eq!(receipt.deadline_met(), Some(false));
    assert!(receipt.sanitized_artifact_overwrite_attempted());
    Ok(())
}

#[test]
fn aborted_session_without_source_disposes_empty_controlled_root() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session()?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    session.apply(SessionAction::Abort)?;

    let mut prepared = prepare_terminal_disposition(&parent, &session, root, lease, None)?;
    let receipt = prepared
        .dispose(&mut session)?
        .ok_or_else(|| io::Error::other("terminal disposition did not complete"))?;

    assert_eq!(session.state(), SessionState::Disposed);
    assert_eq!(receipt.disposition_reason(), DispositionReason::Aborted);
    assert_eq!(receipt.source_commitment_sha256(), None);
    assert_eq!(receipt.sanitized_commitment_sha256(), None);
    assert!(!receipt.sanitized_artifact_overwrite_attempted());
    assert!(!temp.staging_path(SESSION).exists());
    Ok(())
}

#[test]
fn public_surface_is_redacted_and_not_protocol_reachable() {
    let disposition = include_str!("../src/disposition.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");

    for marker in [
        "systeme-local:operator-evidence-retention-decision:v1\\0",
        "systeme-local:operator-evidence-logical-disposition:v1\\0",
        "pub struct PreparedDisposition",
        "pub struct RetainedSanitization",
        "pub struct LogicalDispositionReceipt",
    ] {
        assert!(disposition.contains(marker));
    }

    for forbidden in [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "std::process::Command",
        "std::env::var",
        "SystemTime::now",
        "impl Serialize for PreparedDisposition",
        "impl Serialize for RetainedSanitization",
    ] {
        assert!(!disposition.contains(forbidden));
    }

    for boundary in [protocol, binary] {
        for forbidden in [
            "PreparedDisposition",
            "RetainedSanitization",
            "LogicalDispositionReceipt",
            "prepare_sanitized_disposition",
            "prepare_terminal_disposition",
            "operator-evidence-logical-disposition",
        ] {
            assert!(!boundary.contains(forbidden));
        }
    }
}
