use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use systeme_local_operator_evidence_custodian::{
    ControlledReadError, ControlledSanitizationError, ControlledStagingRoot, CustodySession,
    SanitizationError, SanitizedOutputClass, SanitizerProfileId, SessionAction, SessionId,
    SourceName, SourceReadError, SourceReadLimit, StagingParent,
    commit_controlled_synthetic_source, sanitize_controlled_synthetic_source,
};

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
const OTHER_SESSION: &str = "ses_fedcba9876543210fedcba9876543210";
const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";
const UI_EXPORT: &[u8] = b"access_control=restricted\naction_review=approved\napp_state=draft\nauthentication=available\ntool_scan=passed\ntransport=available\n";
const GOLDEN_SOURCE_COMMITMENT: &str =
    "c6ab60e8cf3efb1abe5de9f9d0d6d533b25d8683fbac843749b2a3b7434bc64f";
const GOLDEN_SANITIZED_COMMITMENT: &str =
    "1eb777edda513a56879e56268378a0af6c7c0ec490fefc3d19511d70f80b1aa3";

struct TempParent {
    path: PathBuf,
}

impl TempParent {
    fn new() -> io::Result<Self> {
        let parent = std::env::temp_dir();

        for _ in 0..100 {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "systeme-local-deterministic-sanitization-{}-{nonce}",
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
            "unable to allocate deterministic-sanitization test parent",
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

fn created_session(value: &str) -> Result<CustodySession, Box<dyn Error>> {
    Ok(CustodySession::new(SessionId::from_str(value)?))
}

fn write_source(temp: &TempParent, session: &str, bytes: &[u8]) -> io::Result<()> {
    fs::write(temp.staging_path(session).join(SOURCE), bytes)
}

#[test]
fn controlled_sanitization_is_deterministic_and_matches_the_golden_fixture()
-> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, UI_EXPORT)?;
    session.apply(SessionAction::BeginCollection)?;
    let source_commitment = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;

    let first = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &source_commitment,
        SanitizerProfileId::UiExportV1,
    )?;
    let second = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &source_commitment,
        SanitizerProfileId::UiExportV1,
    )?;

    assert_eq!(
        source_commitment.commitment_sha256(),
        GOLDEN_SOURCE_COMMITMENT
    );
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first.artifact().byte_len(), UI_EXPORT.len());
    assert_eq!(
        first.artifact().output_class(),
        SanitizedOutputClass::CanonicalUtf8Text
    );
    assert_eq!(
        first.receipt().sanitized_commitment_sha256(),
        GOLDEN_SANITIZED_COMMITMENT
    );
    Ok(())
}

#[test]
fn all_profiles_are_reachable_only_through_the_controlled_boundary() -> Result<(), Box<dyn Error>> {
    let fixtures: [(SanitizerProfileId, &[u8]); 5] = [
        (SanitizerProfileId::UiExportV1, UI_EXPORT),
        (
            SanitizerProfileId::MetadataDocumentV1,
            b"{\"authorization_code\":true,\"document_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"pkce\":true,\"refresh_token\":false,\"token_auth_method\":\"none\"}",
        ),
        (
            SanitizerProfileId::ToolScanSnapshotV1,
            b"{\"capability_count\":3,\"destructive_count\":1,\"read_only_count\":2,\"snapshot_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"unknown_count\":0}",
        ),
        (
            SanitizerProfileId::ActionReviewSnapshotV1,
            b"{\"action_count\":3,\"approved_count\":2,\"blocked_count\":1,\"snapshot_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"unknown_count\":0}",
        ),
        (
            SanitizerProfileId::LocalPolicySnapshotV1,
            b"approval=required\nnetwork=disabled\nretention=ephemeral\nsecrets=absent\nworkspace=isolated\n",
        ),
    ];

    for (index, (profile_id, input)) in fixtures.into_iter().enumerate() {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let session_text = format!("ses_{index:032x}");
        let mut session = created_session(&session_text)?;
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
        write_source(&temp, &session_text, input)?;
        session.apply(SessionAction::BeginCollection)?;
        let source_commitment = commit_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &source_name()?,
            SourceReadLimit::new(4096)?,
        )?;
        let result = sanitize_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &source_name()?,
            &source_commitment,
            profile_id,
        )?;

        assert_eq!(result.receipt().profile_id(), profile_id);
        assert_eq!(result.receipt().profile_version(), 1);
        assert_eq!(
            result.receipt().source_commitment_sha256(),
            source_commitment.commitment_sha256()
        );
        assert!(!result.artifact().is_empty());
    }

    Ok(())
}

#[test]
fn custody_and_source_commitment_mismatches_fail_before_sanitization() -> Result<(), Box<dyn Error>>
{
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, UI_EXPORT)?;

    let receipt_temp = TempParent::new()?;
    let receipt_parent = StagingParent::open(&receipt_temp.path)?;
    let mut receipt_session = created_session(OTHER_SESSION)?;
    let (receipt_root, receipt_lease) =
        ControlledStagingRoot::create(&receipt_parent, &receipt_session)?;
    write_source(&receipt_temp, OTHER_SESSION, UI_EXPORT)?;
    receipt_session.apply(SessionAction::BeginCollection)?;
    let unrelated_commitment = commit_controlled_synthetic_source(
        &receipt_session,
        &receipt_root,
        &receipt_lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;

    let before_collection = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &unrelated_commitment,
        SanitizerProfileId::UiExportV1,
    );
    assert!(matches!(
        before_collection,
        Err(ControlledSanitizationError::Read(
            ControlledReadError::Source(SourceReadError::SessionNotCollecting)
        ))
    ));

    let mut mismatched_session = created_session(OTHER_SESSION)?;
    mismatched_session.apply(SessionAction::BeginCollection)?;
    let custody_mismatch = sanitize_controlled_synthetic_source(
        &mismatched_session,
        &root,
        &lease,
        &source_name()?,
        &unrelated_commitment,
        SanitizerProfileId::UiExportV1,
    );
    assert!(matches!(
        custody_mismatch,
        Err(ControlledSanitizationError::Read(
            ControlledReadError::SessionMismatch
        ))
    ));

    session.apply(SessionAction::BeginCollection)?;
    let commitment = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(512)?,
    )?;
    write_source(&temp, SESSION, b"not-a-closed-ui-export")?;
    let mismatch = sanitize_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        &commitment,
        SanitizerProfileId::UiExportV1,
    );
    assert!(matches!(
        mismatch,
        Err(ControlledSanitizationError::Sanitization(
            SanitizationError::SourceCommitmentMismatch
        ))
    ));
    Ok(())
}

#[test]
fn public_surface_is_redacted_and_protocol_v1_remains_unreachable() {
    let sanitizer = include_str!("../src/sanitizer.rs");
    let source = include_str!("../src/source.rs");
    let staging = include_str!("../src/staging.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");

    assert!(sanitizer.contains("systeme-local:operator-evidence-sanitized-output:v1\\0"));
    assert!(sanitizer.contains("pub struct SanitizedArtifact"));
    assert!(sanitizer.contains("self.bytes.fill(0);"));
    assert!(!sanitizer.contains("pub fn commitment_bytes"));
    assert!(!source.contains("pub fn sanitizer_bytes"));
    assert!(staging.contains("pub fn sanitize_controlled_synthetic_source"));
    for forbidden in [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "std::process",
        "Command::",
        "std::env::var",
        "impl Serialize for SanitizedArtifact",
        "impl Deserialize for SanitizedArtifact",
    ] {
        assert!(!sanitizer.contains(forbidden));
    }

    for boundary in [protocol, binary] {
        for forbidden in [
            "SanitizedArtifact",
            "SanitizedOutputReceipt",
            "sanitize_controlled_synthetic_source",
            "systeme-local:operator-evidence-sanitized-output",
        ] {
            assert!(!boundary.contains(forbidden));
        }
    }
    assert!(protocol.contains("sanitizer_execution: RequiredFalse"));
}
