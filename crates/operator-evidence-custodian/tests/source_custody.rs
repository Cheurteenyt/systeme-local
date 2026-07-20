use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use systeme_local_operator_evidence_custodian::{
    CustodySession, SessionAction, SessionId, SourceName, SourceReadLimit, StagingRoot,
    read_synthetic_source,
};

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> io::Result<Self> {
        let parent = std::env::temp_dir();

        for _ in 0..100 {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "systeme-local-source-public-{}-{nonce}",
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
            "unable to allocate synthetic public test directory",
        ))
    }

    fn staging_path(&self) -> PathBuf {
        self.path.join("staging")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn public_surface_exposes_only_redacted_metadata() -> Result<(), Box<dyn Error>> {
    let temp = TempRoot::new()?;
    let staging_path = temp.staging_path();
    fs::create_dir(&staging_path)?;
    fs::write(staging_path.join(SOURCE), b"synthetic-public-contract")?;

    let staging = StagingRoot::open(&staging_path)?;
    let mut session =
        CustodySession::new(SessionId::from_str("ses_0123456789abcdef0123456789abcdef")?);
    session.apply(SessionAction::BeginCollection)?;

    let guarded = read_synthetic_source(
        &session,
        &staging,
        &SourceName::from_str(SOURCE)?,
        SourceReadLimit::new(64)?,
    )?;

    assert_eq!(guarded.byte_len(), 25);
    assert!(!guarded.is_empty());

    let rendered = format!("{guarded:?}");
    assert!(rendered.contains("byte_len"));
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("synthetic-public-contract"));
    assert!(!rendered.contains(&staging_path.to_string_lossy().to_string()));
    Ok(())
}

#[test]
fn source_module_has_no_serialization_network_or_public_byte_getter() {
    let source = include_str!("../src/source.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");

    for forbidden in [
        "Serialize",
        "Deserialize",
        "serde_json",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "pub fn bytes",
        "pub fn as_bytes",
        "pub fn into_bytes",
    ] {
        assert!(!source.contains(forbidden));
    }

    for boundary in [protocol, binary] {
        assert!(!boundary.contains("read_synthetic_source"));
        assert!(!boundary.contains("StagingRoot"));
        assert!(!boundary.contains("SourceName"));
        assert!(!boundary.contains("GuardedSource"));
    }
}

#[test]
fn opaque_source_name_cannot_encode_a_path() {
    for invalid in [
        "../src_0123456789abcdef0123456789abcdef.raw",
        r"..\src_0123456789abcdef0123456789abcdef.raw",
        "/src_0123456789abcdef0123456789abcdef.raw",
        r"C:\src_0123456789abcdef0123456789abcdef.raw",
        "nested/src_0123456789abcdef0123456789abcdef.raw",
        "src_0123456789abcdef0123456789abcdef.raw/child",
    ] {
        assert!(SourceName::from_str(invalid).is_err());
    }
}

#[allow(dead_code)]
fn _path_type_is_test_only(_: &Path) {}
