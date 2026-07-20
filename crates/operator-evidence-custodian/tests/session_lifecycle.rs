use serde_json::Value;
use std::error::Error;
use std::str::FromStr;
use systeme_local_operator_evidence_custodian::{
    CustodySession, SessionAction, SessionId, SessionState, TransitionError,
    compute_transition_sha256,
};

fn session_id() -> Result<SessionId, Box<dyn Error>> {
    Ok(SessionId::from_str("ses_0123456789abcdef0123456789abcdef")?)
}

#[test]
fn happy_path_reaches_disposed_with_monotonic_revisions() -> Result<(), Box<dyn Error>> {
    let mut session = CustodySession::new(session_id()?);

    let collecting = session.apply(SessionAction::BeginCollection)?;
    assert_eq!(collecting.prior_state, SessionState::Created);
    assert_eq!(collecting.resulting_state, SessionState::Collecting);
    assert_eq!(collecting.revision, 1);

    let sealed = session.apply(SessionAction::Seal)?;
    assert_eq!(sealed.prior_state, SessionState::Collecting);
    assert_eq!(sealed.resulting_state, SessionState::Sealed);
    assert_eq!(sealed.revision, 2);

    let retained = session.apply(SessionAction::Retain)?;
    assert_eq!(retained.prior_state, SessionState::Sealed);
    assert_eq!(retained.resulting_state, SessionState::Retained);
    assert_eq!(retained.revision, 3);

    let disposed = session.apply(SessionAction::Dispose)?;
    assert_eq!(disposed.prior_state, SessionState::Retained);
    assert_eq!(disposed.resulting_state, SessionState::Disposed);
    assert_eq!(disposed.revision, 4);
    assert_eq!(session.state(), SessionState::Disposed);
    assert_eq!(session.revision(), 4);
    Ok(())
}

#[test]
fn invalid_transition_preserves_state_and_revision() -> Result<(), Box<dyn Error>> {
    let mut session = CustodySession::new(session_id()?);
    let original = session.clone();
    let result = session.apply(SessionAction::Seal);

    assert_eq!(
        result,
        Err(TransitionError::InvalidTransition {
            prior_state: SessionState::Created,
            action: SessionAction::Seal,
        })
    );
    assert_eq!(session, original);
    Ok(())
}

#[test]
fn disposed_is_terminal() -> Result<(), Box<dyn Error>> {
    let mut session = CustodySession::new(session_id()?);
    session.apply(SessionAction::Abort)?;
    session.apply(SessionAction::Dispose)?;
    let original = session.clone();

    for action in [
        SessionAction::BeginCollection,
        SessionAction::Seal,
        SessionAction::Retain,
        SessionAction::Abort,
        SessionAction::Expire,
        SessionAction::Dispose,
    ] {
        let result = session.apply(action);
        assert_eq!(
            result,
            Err(TransitionError::InvalidTransition {
                prior_state: SessionState::Disposed,
                action,
            })
        );
        assert_eq!(session, original);
    }
    Ok(())
}

#[test]
fn receipt_serialization_is_exact_and_secret_free() -> Result<(), Box<dyn Error>> {
    let mut session = CustodySession::new(session_id()?);
    let receipt = session.apply(SessionAction::BeginCollection)?;
    let serialized = serde_json::to_string(&receipt)?;

    assert_eq!(
        serialized,
        concat!(
            "{\"session_id\":\"ses_0123456789abcdef0123456789abcdef\",",
            "\"prior_state\":\"created\",",
            "\"action\":\"begin_collection\",",
            "\"resulting_state\":\"collecting\",",
            "\"revision\":1,",
            "\"transition_sha256\":",
            "\"3d25cf9cd59e7d6e17b792c0071535f7a56fb91f84b196f82aba506cd5df8798\"}"
        )
    );

    let value: Value = serde_json::from_str(&serialized)?;
    for forbidden in [
        "path",
        "endpoint",
        "credential",
        "secret",
        "token",
        "raw_evidence",
        "timestamp",
        "environment",
    ] {
        assert!(value.get(forbidden).is_none());
    }
    Ok(())
}

#[test]
fn identifiers_and_enum_values_reject_noncanonical_input() {
    for invalid in [
        "ses_0123456789abcdef0123456789abcde",
        "ses_0123456789abcdef0123456789abcdef0",
        "ses_0123456789ABCDEF0123456789ABCDEF",
        "session_0123456789abcdef0123456789abcdef",
        "ses_../../../../windows/system32",
        "ses_0123456789abcdef/123456789abcdef",
        "ses_0123456789abcdef_123456789abcdef",
    ] {
        assert!(SessionId::from_str(invalid).is_err());
        let encoded = serde_json::to_string(invalid).unwrap_or_default();
        assert!(serde_json::from_str::<SessionId>(&encoded).is_err());
    }

    assert!(serde_json::from_str::<SessionState>("\"unknown\"").is_err());
    assert!(serde_json::from_str::<SessionAction>("\"delete_source\"").is_err());
}

#[test]
fn transition_commitment_is_deterministic_and_field_bound() -> Result<(), Box<dyn Error>> {
    let id = session_id()?;
    let first = compute_transition_sha256(
        &id,
        SessionState::Created,
        SessionAction::BeginCollection,
        SessionState::Collecting,
        1,
    );
    let second = compute_transition_sha256(
        &id,
        SessionState::Created,
        SessionAction::BeginCollection,
        SessionState::Collecting,
        1,
    );
    let different_revision = compute_transition_sha256(
        &id,
        SessionState::Created,
        SessionAction::BeginCollection,
        SessionState::Collecting,
        2,
    );

    assert_eq!(first, second);
    assert_ne!(first, different_revision);
    assert_eq!(first.len(), 64);
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn session_module_contains_no_io_or_network_capability() {
    let source = include_str!("../src/session.rs");

    for forbidden in [
        "std::fs",
        "std::io",
        "std::net",
        "PathBuf",
        "TcpStream",
        "UdpSocket",
        "File::open",
        "OpenOptions",
    ] {
        assert!(!source.contains(forbidden));
    }
}
