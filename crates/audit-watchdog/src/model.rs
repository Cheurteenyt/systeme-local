use serde::{Deserialize, Serialize};

use crate::Digest;

pub(crate) const FORMAT_VERSION: u64 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapReceipt {
    pub version: u64,
    pub created_at_utc: String,
    pub git_commit: String,
    pub anchor_path: String,
    pub records: u64,
    pub last_hmac: Digest,
    pub checkpoint_hmac: Digest,
    pub anchor_sha256: Digest,
    pub storage_profile: StorageProfile,
    pub rollback_domain: RollbackDomain,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorCheckpoint {
    pub version: u64,
    pub checkpoint_id: String,
    pub timestamp: String,
    pub audit_log_id: Digest,
    pub records: u64,
    pub last_hmac: Digest,
    pub previous_checkpoint_hmac: Digest,
    pub checkpoint_hmac: Digest,
}

/// Storage profile declared by the bootstrap receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StorageProfile {
    /// A same-project NTFS directory with protected ACL inheritance.
    #[serde(rename = "local-ntfs-hardened")]
    LocalNtfsHardened,
}

/// Rollback boundary declared by the bootstrap receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RollbackDomain {
    /// The anchor and audit log remain on the same restorable volume.
    #[serde(rename = "same-volume-as-audit-log")]
    SameVolumeAsAuditLog,
}

/// Scope of the independent verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationScope {
    /// The verifier uses only public witness data and never reads HMAC keys.
    NonSecretWitnessConsistency,
}

/// Successful verification details.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationReport {
    /// Format version accepted by the verifier.
    pub version: u64,
    /// Explicit boundary of what this report proves.
    pub scope: VerificationScope,
    /// Storage profile declared by the receipt.
    pub storage_profile: StorageProfile,
    /// Rollback boundary declared by the receipt.
    pub rollback_domain: RollbackDomain,
    /// Number of checkpoint lines validated.
    pub checkpoints: usize,
    /// Audit-record count at explicit bootstrap.
    pub bootstrap_records: u64,
    /// Latest checkpoint audit-record count.
    pub current_records: u64,
    /// Latest audit-chain HMAC recorded by the anchor.
    pub current_last_hmac: Digest,
    /// Checkpoint HMAC referenced by the bootstrap receipt.
    pub bootstrap_checkpoint_hmac: Digest,
    /// SHA-256 of the exact anchor prefix present at bootstrap.
    pub bootstrap_prefix_sha256: Digest,
    /// Whether additional validly chained checkpoints exist after bootstrap.
    pub advanced_since_bootstrap: bool,
    /// Authentication is deliberately not claimed without the secret key.
    pub cryptographic_authentication_performed: bool,
}
