use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use systeme_local_operator_evidence_custodian::{
    ControlledStagingRoot, CustodySession, SessionId, StagingParent,
};

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";

struct TempParent {
    path: PathBuf,
}

impl TempParent {
    fn new() -> io::Result<Self> {
        let parent = std::env::temp_dir();

        for _ in 0..100 {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "systeme-local-controlled-public-{}-{nonce}",
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
            "unable to allocate controlled public test directory",
        ))
    }
}

impl Drop for TempParent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn public_controlled_surface_is_opaque_and_reacquirable() -> Result<(), Box<dyn Error>> {
    let temp = TempParent::new()?;
    let parent = StagingParent::open(&temp.path)?;
    let session = CustodySession::new(SessionId::from_str(SESSION)?);
    let (root, first) = ControlledStagingRoot::create(&parent, &session)?;

    assert!(first.is_active());

    for rendered in [
        format!("{parent:?}"),
        format!("{root:?}"),
        format!("{first:?}"),
    ] {
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains(SESSION));
        assert!(!rendered.contains(&temp.path.to_string_lossy().to_string()));
    }

    drop(first);
    let second = root.acquire_lease(&session)?;
    assert!(second.is_active());
    Ok(())
}

#[test]
fn staging_module_has_no_serialization_network_or_protocol_reachability() {
    let staging = include_str!("../src/staging.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");

    for forbidden in [
        "Serialize",
        "Deserialize",
        "serde_json",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "pub fn path",
        "pub fn canonical_path",
    ] {
        assert!(!staging.contains(forbidden));
    }

    for boundary in [protocol, binary] {
        assert!(!boundary.contains("ControlledStagingRoot"));
        assert!(!boundary.contains("SessionLease"));
        assert!(!boundary.contains("read_controlled_synthetic_source"));
        assert!(!boundary.contains("StagingParent"));
    }
}
