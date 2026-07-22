use crate::session::{CustodySession, SessionState};
use crate::source::GuardedSource;
use sha2::{Digest, Sha256};
use std::fmt;

const SOURCE_COMMITMENT_DOMAIN: &[u8] = b"systeme-local:operator-evidence-source-commitment:v1\0";

#[derive(Clone, Eq, PartialEq)]
pub struct SourceCommitmentReceipt {
    byte_len: u64,
    commitment_sha256: String,
}

impl SourceCommitmentReceipt {
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[must_use]
    pub fn commitment_sha256(&self) -> &str {
        &self.commitment_sha256
    }
}

impl fmt::Debug for SourceCommitmentReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceCommitmentReceipt")
            .field("byte_len", &self.byte_len)
            .field("commitment_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommitmentError {
    SessionNotCollecting,
    CapacityOverflow,
}

impl fmt::Display for SourceCommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionNotCollecting => "custody session is not collecting",
            Self::CapacityOverflow => "source commitment length overflow",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for SourceCommitmentError {}

pub(crate) fn commit_guarded_source(
    session: &CustodySession,
    source: &GuardedSource,
) -> Result<SourceCommitmentReceipt, SourceCommitmentError> {
    if session.state() != SessionState::Collecting {
        return Err(SourceCommitmentError::SessionNotCollecting);
    }

    let byte_len =
        u64::try_from(source.byte_len()).map_err(|_| SourceCommitmentError::CapacityOverflow)?;
    let mut digest = Sha256::new();
    digest.update(SOURCE_COMMITMENT_DOMAIN);
    update_field(&mut digest, session.session_id().as_str().as_bytes())?;
    digest.update(byte_len.to_be_bytes());
    digest.update(source.commitment_bytes());

    Ok(SourceCommitmentReceipt {
        byte_len,
        commitment_sha256: encode_lower_hex(digest.finalize().as_ref()),
    })
}

fn update_field(digest: &mut Sha256, value: &[u8]) -> Result<(), SourceCommitmentError> {
    let length = u64::try_from(value.len()).map_err(|_| SourceCommitmentError::CapacityOverflow)?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
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

    #[test]
    fn source_commitment_domain_is_exact_and_private() {
        assert_eq!(
            SOURCE_COMMITMENT_DOMAIN,
            b"systeme-local:operator-evidence-source-commitment:v1\0"
        );
        assert_ne!(
            SOURCE_COMMITMENT_DOMAIN,
            b"systeme-local:operator-evidence-custodian-contract:v1\0"
        );
        assert_ne!(
            SOURCE_COMMITMENT_DOMAIN,
            b"systeme-local:operator-evidence-session-transition:v1\0"
        );
    }
}
