use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

const SESSION_ID_PREFIX: &str = "ses_";
const SESSION_ID_HEX_LENGTH: usize = 32;
const TRANSITION_DOMAIN: &[u8] = b"systeme-local:operator-evidence-session-transition:v1\0";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SessionId {
    type Err = SessionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix(SESSION_ID_PREFIX) else {
            return Err(SessionIdError);
        };

        if hex.len() != SESSION_ID_HEX_LENGTH
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SessionIdError);
        }

        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(|_| serde::de::Error::custom("invalid session identifier"))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIdError;

impl fmt::Display for SessionIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid operator-evidence session identifier")
    }
}

impl std::error::Error for SessionIdError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Collecting,
    Sealed,
    Retained,
    Aborted,
    Expired,
    Disposed,
}

impl SessionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Retained => "retained",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
            Self::Disposed => "disposed",
        }
    }

    #[must_use]
    pub const fn transition(self, action: SessionAction) -> Option<Self> {
        match (self, action) {
            (Self::Created, SessionAction::BeginCollection) => Some(Self::Collecting),
            (Self::Created | Self::Collecting, SessionAction::Abort) => Some(Self::Aborted),
            (Self::Created | Self::Collecting, SessionAction::Expire) => Some(Self::Expired),
            (Self::Collecting, SessionAction::Seal) => Some(Self::Sealed),
            (Self::Sealed, SessionAction::Retain) => Some(Self::Retained),
            (
                Self::Sealed | Self::Retained | Self::Aborted | Self::Expired,
                SessionAction::Dispose,
            ) => Some(Self::Disposed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAction {
    BeginCollection,
    Seal,
    Retain,
    Abort,
    Expire,
    Dispose,
}

impl SessionAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeginCollection => "begin_collection",
            Self::Seal => "seal",
            Self::Retain => "retain",
            Self::Abort => "abort",
            Self::Expire => "expire",
            Self::Dispose => "dispose",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidTransition {
        prior_state: SessionState,
        action: SessionAction,
    },
    RevisionOverflow {
        prior_state: SessionState,
        action: SessionAction,
    },
}

impl TransitionError {
    #[must_use]
    pub const fn prior_state(self) -> SessionState {
        match self {
            Self::InvalidTransition { prior_state, .. }
            | Self::RevisionOverflow { prior_state, .. } => prior_state,
        }
    }

    #[must_use]
    pub const fn action(self) -> SessionAction {
        match self {
            Self::InvalidTransition { action, .. } | Self::RevisionOverflow { action, .. } => {
                action
            }
        }
    }
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("invalid custody-session transition")
            }
            Self::RevisionOverflow { .. } => {
                formatter.write_str("custody-session revision overflow")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionTransitionReceipt {
    pub session_id: SessionId,
    pub prior_state: SessionState,
    pub action: SessionAction,
    pub resulting_state: SessionState,
    pub revision: u64,
    pub transition_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodySession {
    session_id: SessionId,
    state: SessionState,
    revision: u64,
}

impl CustodySession {
    #[must_use]
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            state: SessionState::Created,
            revision: 0,
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Applies one authorized lifecycle action.
    ///
    /// # Errors
    ///
    /// Returns a typed error without mutation when the edge is illegal or the
    /// monotonic revision would overflow.
    pub fn apply(
        &mut self,
        action: SessionAction,
    ) -> Result<SessionTransitionReceipt, TransitionError> {
        let prior_state = self.state;
        let resulting_state =
            prior_state
                .transition(action)
                .ok_or(TransitionError::InvalidTransition {
                    prior_state,
                    action,
                })?;
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(TransitionError::RevisionOverflow {
                prior_state,
                action,
            })?;
        let transition_sha256 = compute_transition_sha256(
            &self.session_id,
            prior_state,
            action,
            resulting_state,
            revision,
        );
        let receipt = SessionTransitionReceipt {
            session_id: self.session_id.clone(),
            prior_state,
            action,
            resulting_state,
            revision,
            transition_sha256,
        };

        self.state = resulting_state;
        self.revision = revision;
        Ok(receipt)
    }
}

#[must_use]
pub fn compute_transition_sha256(
    session_id: &SessionId,
    prior_state: SessionState,
    action: SessionAction,
    resulting_state: SessionState,
    revision: u64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(TRANSITION_DOMAIN);
    update_field(&mut digest, session_id.as_str().as_bytes());
    update_field(&mut digest, prior_state.as_str().as_bytes());
    update_field(&mut digest, action.as_str().as_bytes());
    update_field(&mut digest, resulting_state.as_str().as_bytes());
    update_field(&mut digest, revision.to_string().as_bytes());
    encode_lower_hex(digest.finalize().as_ref())
}

fn update_field(digest: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(length.to_be_bytes());
    digest.update(value);
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: [SessionState; 7] = [
        SessionState::Created,
        SessionState::Collecting,
        SessionState::Sealed,
        SessionState::Retained,
        SessionState::Aborted,
        SessionState::Expired,
        SessionState::Disposed,
    ];
    const ACTIONS: [SessionAction; 6] = [
        SessionAction::BeginCollection,
        SessionAction::Seal,
        SessionAction::Retain,
        SessionAction::Abort,
        SessionAction::Expire,
        SessionAction::Dispose,
    ];

    fn session_id() -> SessionId {
        SessionId("ses_0123456789abcdef0123456789abcdef".to_owned())
    }

    #[test]
    fn transition_table_contains_exactly_the_authorized_edges() {
        let expected = [
            (
                SessionState::Created,
                SessionAction::BeginCollection,
                SessionState::Collecting,
            ),
            (
                SessionState::Created,
                SessionAction::Abort,
                SessionState::Aborted,
            ),
            (
                SessionState::Created,
                SessionAction::Expire,
                SessionState::Expired,
            ),
            (
                SessionState::Collecting,
                SessionAction::Seal,
                SessionState::Sealed,
            ),
            (
                SessionState::Collecting,
                SessionAction::Abort,
                SessionState::Aborted,
            ),
            (
                SessionState::Collecting,
                SessionAction::Expire,
                SessionState::Expired,
            ),
            (
                SessionState::Sealed,
                SessionAction::Retain,
                SessionState::Retained,
            ),
            (
                SessionState::Sealed,
                SessionAction::Dispose,
                SessionState::Disposed,
            ),
            (
                SessionState::Retained,
                SessionAction::Dispose,
                SessionState::Disposed,
            ),
            (
                SessionState::Aborted,
                SessionAction::Dispose,
                SessionState::Disposed,
            ),
            (
                SessionState::Expired,
                SessionAction::Dispose,
                SessionState::Disposed,
            ),
        ];

        for state in STATES {
            for action in ACTIONS {
                let expected_state = expected
                    .iter()
                    .find(|(candidate_state, candidate_action, _)| {
                        *candidate_state == state && *candidate_action == action
                    })
                    .map(|(_, _, resulting_state)| *resulting_state);
                assert_eq!(state.transition(action), expected_state);
            }
        }
    }

    #[test]
    fn revision_overflow_is_fail_closed() {
        let mut session = CustodySession {
            session_id: session_id(),
            state: SessionState::Created,
            revision: u64::MAX,
        };
        let original = session.clone();
        let result = session.apply(SessionAction::BeginCollection);

        assert_eq!(
            result,
            Err(TransitionError::RevisionOverflow {
                prior_state: SessionState::Created,
                action: SessionAction::BeginCollection,
            })
        );
        assert_eq!(session, original);
    }

    #[test]
    fn transition_commitment_is_domain_separated() {
        let digest = compute_transition_sha256(
            &session_id(),
            SessionState::Created,
            SessionAction::BeginCollection,
            SessionState::Collecting,
            1,
        );

        assert_eq!(digest.len(), 64);
        assert_ne!(
            digest,
            "ac0b52c54d52e4733dd965b973f08e47e8d1a7435541052262061ad51f51f823"
        );
    }
}
