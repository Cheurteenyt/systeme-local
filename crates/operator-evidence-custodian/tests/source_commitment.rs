use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use systeme_local_operator_evidence_custodian::{
    ControlledCommitmentError, ControlledReadError, ControlledStagingRoot, CustodySession,
    MAX_SYNTHETIC_SOURCE_BYTES, SessionAction, SessionId, SourceName, SourceReadError,
    SourceReadLimit, StagingParent, commit_controlled_synthetic_source,
};

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
const OTHER_SESSION: &str = "ses_fedcba9876543210fedcba9876543210";
const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";
const GOLDEN_COMMITMENT: &str = "15db1fa34400709d24b7476c152886b13a664238e32165d8bb0942182c64e086";

struct TempParent {
    path: PathBuf,
}

impl TempParent {
    fn new() -> io::Result<Self> {
        let parent = std::env::temp_dir();

        for _ in 0..100 {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "systeme-local-source-commitment-{}-{nonce}",
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
            "unable to allocate source-commitment test parent",
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
fn controlled_commitment_is_deterministic_and_matches_the_golden_fixture()
-> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, b"synthetic-commitment")?;
    session.apply(SessionAction::BeginCollection)?;

    let first = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(64)?,
    )?;
    let second = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(64)?,
    )?;

    assert_eq!(first, second);
    assert_eq!(first.byte_len(), 20);
    assert_eq!(first.commitment_sha256(), GOLDEN_COMMITMENT);
    assert!(
        first
            .commitment_sha256()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn session_length_and_each_changed_byte_are_bound() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, b"abc")?;
    session.apply(SessionAction::BeginCollection)?;

    let baseline = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(8)?,
    )?;

    for changed in [&b"xbc"[..], &b"axc"[..], &b"abx"[..], &b"abcx"[..]] {
        write_source(&temp, SESSION, changed)?;
        let receipt = commit_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &source_name()?,
            SourceReadLimit::new(8)?,
        )?;
        assert_ne!(receipt.commitment_sha256(), baseline.commitment_sha256());
    }

    let other_temp = TempParent::new()?;
    let other_parent = StagingParent::open(&other_temp.path)?;
    let mut other_session = created_session(OTHER_SESSION)?;
    let (other_root, other_lease) = ControlledStagingRoot::create(&other_parent, &other_session)?;
    write_source(&other_temp, OTHER_SESSION, b"abc")?;
    other_session.apply(SessionAction::BeginCollection)?;
    let other = commit_controlled_synthetic_source(
        &other_session,
        &other_root,
        &other_lease,
        &source_name()?,
        SourceReadLimit::new(8)?,
    )?;

    assert_ne!(other.commitment_sha256(), baseline.commitment_sha256());
    Ok(())
}

#[test]
fn zero_length_and_exact_custody_limit_sources_succeed() -> Result<(), Box<dyn Error>> {
    let empty_temp = TempParent::new()?;
    let empty_parent = StagingParent::open(&empty_temp.path)?;
    let mut empty_session = created_session(SESSION)?;
    let (empty_root, empty_lease) = ControlledStagingRoot::create(&empty_parent, &empty_session)?;
    write_source(&empty_temp, SESSION, b"")?;
    empty_session.apply(SessionAction::BeginCollection)?;
    let empty = commit_controlled_synthetic_source(
        &empty_session,
        &empty_root,
        &empty_lease,
        &source_name()?,
        SourceReadLimit::new(1)?,
    )?;
    assert_eq!(empty.byte_len(), 0);

    let limit_temp = TempParent::new()?;
    let limit_parent = StagingParent::open(&limit_temp.path)?;
    let mut limit_session = created_session(OTHER_SESSION)?;
    let (limit_root, limit_lease) = ControlledStagingRoot::create(&limit_parent, &limit_session)?;
    let exact = vec![0x5a; usize::try_from(MAX_SYNTHETIC_SOURCE_BYTES)?];
    write_source(&limit_temp, OTHER_SESSION, &exact)?;
    limit_session.apply(SessionAction::BeginCollection)?;
    let receipt = commit_controlled_synthetic_source(
        &limit_session,
        &limit_root,
        &limit_lease,
        &source_name()?,
        SourceReadLimit::new(MAX_SYNTHETIC_SOURCE_BYTES)?,
    )?;
    assert_eq!(receipt.byte_len(), MAX_SYNTHETIC_SOURCE_BYTES);
    Ok(())
}

#[test]
fn state_and_lease_mismatch_fail_before_a_commitment() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, b"synthetic")?;

    let before_collection = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(64)?,
    );
    assert!(matches!(
        before_collection,
        Err(ControlledCommitmentError::Read(
            ControlledReadError::Source(SourceReadError::SessionNotCollecting)
        ))
    ));

    session.apply(SessionAction::BeginCollection)?;
    let other = created_session(OTHER_SESSION)?;
    let mismatch = commit_controlled_synthetic_source(
        &other,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(64)?,
    );
    assert!(matches!(
        mismatch,
        Err(ControlledCommitmentError::Read(
            ControlledReadError::SessionMismatch
        ))
    ));
    Ok(())
}

#[test]
fn receipt_and_errors_are_redacted_and_not_wire_reachable() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let mut session = created_session(SESSION)?;
    let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
    write_source(&temp, SESSION, b"highly-private-commitment-bytes")?;
    session.apply(SessionAction::BeginCollection)?;

    let receipt = commit_controlled_synthetic_source(
        &session,
        &root,
        &lease,
        &source_name()?,
        SourceReadLimit::new(64)?,
    )?;
    let receipt_debug = format!("{receipt:?}");
    let error_debug = format!(
        "{:?}",
        ControlledCommitmentError::Read(ControlledReadError::LeaseInactive)
    );
    let private_path = temp.path.to_string_lossy();

    for rendered in [receipt_debug.as_str(), error_debug.as_str()] {
        assert!(!rendered.contains("highly-private"));
        assert!(!rendered.contains(SESSION));
        assert!(!rendered.contains(SOURCE));
        assert!(!rendered.contains(private_path.as_ref()));
    }
    assert!(receipt_debug.contains("[redacted]"));

    let commitment = include_str!("../src/commitment.rs");
    let source = include_str!("../src/source.rs");
    let staging = include_str!("../src/staging.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");
    let provider_models = include_str!(
        "../../../src/systeme_local_gateway/providers/mcp_operator_evidence_models.py"
    );

    assert!(commitment.contains("systeme-local:operator-evidence-source-commitment:v1\\0"));
    assert!(commitment.contains(
        "pub struct SourceCommitmentReceipt {\n    byte_len: u64,\n    commitment_sha256: String,"
    ));
    assert!(!provider_models.contains("systeme-local:operator-evidence-source-commitment:v1"));
    assert!(!source.contains("pub fn commitment_bytes"));
    for forbidden in ["Serialize", "Deserialize", "serde_json", "std::net"] {
        assert!(!commitment.contains(forbidden));
    }
    for boundary in [protocol, binary] {
        for forbidden in [
            "SourceCommitmentReceipt",
            "commit_controlled_synthetic_source",
            "SanitizerProfileId",
        ] {
            assert!(!boundary.contains(forbidden));
        }
    }
    let Some(controlled_start) = staging.find("pub fn commit_controlled_synthetic_source(") else {
        return Err(io::Error::other("controlled commitment entry point is absent").into());
    };
    let controlled_body = &staging[controlled_start..];
    let Some(read_position) = controlled_body.find("read_controlled_synthetic_source(") else {
        return Err(io::Error::other("controlled read is absent from commitment path").into());
    };
    let Some(commit_position) = controlled_body.find("commit_guarded_source(") else {
        return Err(io::Error::other("private commitment call is absent").into());
    };
    assert!(read_position < commit_position);
    Ok(())
}
