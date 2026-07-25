use crate::commitment::SourceCommitmentReceipt;
use crate::sanitizer::{SanitizationResult, SanitizedArtifact, SanitizedOutputReceipt};
use crate::session::{
    CustodySession, SessionAction, SessionState, SessionTransitionReceipt, TransitionError,
};
use crate::source::SourceName;
use crate::staging::{
    ControlledStagingRoot, DispositionStaging, DispositionStagingError, SessionLease,
    StagingParent, prepare_disposition_staging,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

const RETENTION_DECISION_DOMAIN: &[u8] = b"systeme-local:operator-evidence-retention-decision:v1\0";
const LOGICAL_DISPOSITION_DOMAIN: &[u8] =
    b"systeme-local:operator-evidence-logical-disposition:v1\0";
const ABSENT_MARKER: &str = "absent";
const NOT_APPLICABLE_MARKER: &str = "not_applicable";
const MAX_RETENTION_WINDOW_SECONDS: u64 = 900;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    DisposeImmediately,
    RetainUntil,
}

impl RetentionMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisposeImmediately => "dispose_immediately",
            Self::RetainUntil => "retain_until",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionOwner {
    LocalOperator,
}

impl RetentionOwner {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOperator => "local_operator",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionDecisionError {
    InvalidJustification,
    InvalidWindow,
}

impl fmt::Display for RetentionDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidJustification => "invalid retention justification commitment",
            Self::InvalidWindow => "invalid bounded retention window",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RetentionDecisionError {}

#[derive(Clone, Eq, PartialEq)]
pub struct RetentionDecision {
    mode: RetentionMode,
    owner: RetentionOwner,
    justification_sha256: String,
    decided_at_unix_seconds: u64,
    dispose_by_unix_seconds: u64,
    retention_window_seconds: u64,
}

impl RetentionDecision {
    /// Constructs an immediate logical-disposition decision.
    ///
    /// # Errors
    ///
    /// Returns an error when `justification_sha256` is not canonical lowercase SHA-256.
    pub fn dispose_immediately(
        justification_sha256: &str,
        decided_at_unix_seconds: u64,
    ) -> Result<Self, RetentionDecisionError> {
        validate_justification(justification_sha256)?;
        Ok(Self {
            mode: RetentionMode::DisposeImmediately,
            owner: RetentionOwner::LocalOperator,
            justification_sha256: justification_sha256.to_owned(),
            decided_at_unix_seconds,
            dispose_by_unix_seconds: decided_at_unix_seconds,
            retention_window_seconds: 0,
        })
    }

    /// Constructs one bounded sanitized-artifact retention decision.
    ///
    /// # Errors
    ///
    /// Returns an error unless the justification is canonical lowercase SHA-256 and the
    /// retention window is within `1..=900` seconds.
    pub fn retain_until(
        justification_sha256: &str,
        decided_at_unix_seconds: u64,
        dispose_by_unix_seconds: u64,
    ) -> Result<Self, RetentionDecisionError> {
        validate_justification(justification_sha256)?;
        let retention_window_seconds = dispose_by_unix_seconds
            .checked_sub(decided_at_unix_seconds)
            .ok_or(RetentionDecisionError::InvalidWindow)?;

        if !(1..=MAX_RETENTION_WINDOW_SECONDS).contains(&retention_window_seconds) {
            return Err(RetentionDecisionError::InvalidWindow);
        }

        Ok(Self {
            mode: RetentionMode::RetainUntil,
            owner: RetentionOwner::LocalOperator,
            justification_sha256: justification_sha256.to_owned(),
            decided_at_unix_seconds,
            dispose_by_unix_seconds,
            retention_window_seconds,
        })
    }

    #[must_use]
    pub const fn mode(&self) -> RetentionMode {
        self.mode
    }

    #[must_use]
    pub const fn owner(&self) -> RetentionOwner {
        self.owner
    }

    #[must_use]
    pub const fn decided_at_unix_seconds(&self) -> u64 {
        self.decided_at_unix_seconds
    }

    #[must_use]
    pub const fn dispose_by_unix_seconds(&self) -> u64 {
        self.dispose_by_unix_seconds
    }

    #[must_use]
    pub const fn retention_window_seconds(&self) -> u64 {
        self.retention_window_seconds
    }
}

impl fmt::Debug for RetentionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionDecision")
            .field("mode", &self.mode)
            .field("owner", &self.owner)
            .field("justification_sha256", &"[redacted]")
            .field("decided_at_unix_seconds", &"[redacted]")
            .field("dispose_by_unix_seconds", &"[redacted]")
            .field("retention_window_seconds", &self.retention_window_seconds)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionReason {
    Completed,
    RetentionReleased,
    Aborted,
    Expired,
}

impl DispositionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::RetentionReleased => "retention_released",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispositionProgress {
    Prepared,
    SourceAbsent,
    LeaseAbsent,
    RootAbsent,
    ArtifactOverwritten,
    SessionDisposed,
    Complete,
}

impl DispositionProgress {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::SourceAbsent => "source_absent",
            Self::LeaseAbsent => "lease_absent",
            Self::RootAbsent => "root_absent",
            Self::ArtifactOverwritten => "artifact_overwritten",
            Self::SessionDisposed => "session_disposed",
            Self::Complete => "complete",
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct LogicalDispositionReceipt {
    prior_state: SessionState,
    resulting_state: SessionState,
    revision: u64,
    transition_sha256: String,
    source_commitment_sha256: Option<String>,
    sanitized_commitment_sha256: Option<String>,
    retention_decision_sha256: Option<String>,
    disposition_reason: DispositionReason,
    raw_source_absent: bool,
    lease_absent: bool,
    staging_root_absent: bool,
    sanitized_artifact_overwrite_attempted: bool,
    deadline_met: Option<bool>,
    logical_disposition_sha256: String,
}

impl LogicalDispositionReceipt {
    #[must_use]
    pub const fn prior_state(&self) -> SessionState {
        self.prior_state
    }

    #[must_use]
    pub const fn resulting_state(&self) -> SessionState {
        self.resulting_state
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn transition_sha256(&self) -> &str {
        &self.transition_sha256
    }

    #[must_use]
    pub fn source_commitment_sha256(&self) -> Option<&str> {
        self.source_commitment_sha256.as_deref()
    }

    #[must_use]
    pub fn sanitized_commitment_sha256(&self) -> Option<&str> {
        self.sanitized_commitment_sha256.as_deref()
    }

    #[must_use]
    pub fn retention_decision_sha256(&self) -> Option<&str> {
        self.retention_decision_sha256.as_deref()
    }

    #[must_use]
    pub const fn disposition_reason(&self) -> DispositionReason {
        self.disposition_reason
    }

    #[must_use]
    pub const fn raw_source_absent(&self) -> bool {
        self.raw_source_absent
    }

    #[must_use]
    pub const fn lease_absent(&self) -> bool {
        self.lease_absent
    }

    #[must_use]
    pub const fn staging_root_absent(&self) -> bool {
        self.staging_root_absent
    }

    #[must_use]
    pub const fn sanitized_artifact_overwrite_attempted(&self) -> bool {
        self.sanitized_artifact_overwrite_attempted
    }

    #[must_use]
    pub const fn deadline_met(&self) -> Option<bool> {
        self.deadline_met
    }

    #[must_use]
    pub fn logical_disposition_sha256(&self) -> &str {
        &self.logical_disposition_sha256
    }
}

impl fmt::Debug for LogicalDispositionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalDispositionReceipt")
            .field("prior_state", &self.prior_state)
            .field("resulting_state", &self.resulting_state)
            .field("revision", &self.revision)
            .field("transition_sha256", &"[redacted]")
            .field("source_commitment_sha256", &"[redacted]")
            .field("sanitized_commitment_sha256", &"[redacted]")
            .field("retention_decision_sha256", &"[redacted]")
            .field("disposition_reason", &self.disposition_reason)
            .field("raw_source_absent", &self.raw_source_absent)
            .field("lease_absent", &self.lease_absent)
            .field("staging_root_absent", &self.staging_root_absent)
            .field(
                "sanitized_artifact_overwrite_attempted",
                &self.sanitized_artifact_overwrite_attempted,
            )
            .field("deadline_met", &self.deadline_met)
            .field("logical_disposition_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispositionError {
    InvalidSessionState,
    SessionMismatch,
    InvalidOperation,
    SourceVerification,
    UnexpectedStagingEntry,
    SourceRemoval,
    LeaseRelease,
    RootRemoval,
    ArtifactUnavailable,
    CapacityOverflow,
    Transition(TransitionError),
    #[cfg(test)]
    InjectedFailure(DispositionProgress),
}

impl fmt::Display for DispositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSessionState => "custody session is not ready for disposition",
            Self::SessionMismatch => "custody session does not match the prepared disposition",
            Self::InvalidOperation => "invalid retention or disposition operation",
            Self::SourceVerification => "controlled source verification failed before disposition",
            Self::UnexpectedStagingEntry => "controlled staging contains an unexpected entry",
            Self::SourceRemoval => "controlled source logical removal failed",
            Self::LeaseRelease => "controlled lease logical release failed",
            Self::RootRemoval => "controlled staging-root logical removal failed",
            Self::ArtifactUnavailable => "sanitized artifact is unavailable",
            Self::CapacityOverflow => "disposition commitment capacity overflow",
            Self::Transition(_) => "custody-session disposition transition failed",
            #[cfg(test)]
            Self::InjectedFailure(_) => "deterministic disposition test failure",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DispositionError {}

#[derive(Clone, Eq, PartialEq)]
struct BoundRetentionDecision {
    decision: RetentionDecision,
    retention_decision_sha256: String,
}

#[allow(clippy::large_enum_variant)]
enum PreparedKind {
    Sanitized {
        artifact: Option<SanitizedArtifact>,
        receipt: SanitizedOutputReceipt,
        retention: BoundRetentionDecision,
    },
    Terminal,
}

pub struct PreparedDisposition {
    session_id: String,
    progress: DispositionProgress,
    staging: Option<DispositionStaging>,
    kind: PreparedKind,
    source_commitment_sha256: Option<String>,
    reason: DispositionReason,
    deadline_met: Option<bool>,
    artifact_overwrite_attempted: bool,
    transition: Option<SessionTransitionReceipt>,
    receipt: Option<LogicalDispositionReceipt>,
    #[cfg(test)]
    fail_before: Option<DispositionProgress>,
}

impl PreparedDisposition {
    #[must_use]
    pub const fn progress(&self) -> DispositionProgress {
        self.progress
    }

    /// Completes an immediate or terminal logical disposition.
    ///
    /// # Errors
    ///
    /// Returns a typed path-free error while retaining monotonic progress for retry.
    pub fn dispose(
        &mut self,
        session: &mut CustodySession,
    ) -> Result<Option<LogicalDispositionReceipt>, DispositionError> {
        if session.session_id().as_str() != self.session_id.as_str() {
            return Err(DispositionError::SessionMismatch);
        }
        if let Some(receipt) = &self.receipt {
            if session.state() != SessionState::Disposed || session.revision() != receipt.revision()
            {
                return Err(DispositionError::InvalidSessionState);
            }
            return Ok(Some(receipt.clone()));
        }
        if matches!(
            &self.kind,
            PreparedKind::Sanitized {
                retention: BoundRetentionDecision {
                    decision: RetentionDecision {
                        mode: RetentionMode::RetainUntil,
                        ..
                    },
                    ..
                },
                ..
            }
        ) && session.state() == SessionState::Sealed
        {
            return Err(DispositionError::InvalidOperation);
        }

        self.advance_raw_cleanup(session)?;

        if self.progress == DispositionProgress::RootAbsent {
            self.maybe_fail(DispositionProgress::ArtifactOverwritten)?;
            if let PreparedKind::Sanitized { artifact, .. } = &mut self.kind {
                let mut artifact = artifact
                    .take()
                    .ok_or(DispositionError::ArtifactUnavailable)?;
                self.artifact_overwrite_attempted = artifact.overwrite_for_disposition();
                drop(artifact);
            }
            self.progress = DispositionProgress::ArtifactOverwritten;
        }

        if self.progress == DispositionProgress::ArtifactOverwritten {
            self.maybe_fail(DispositionProgress::SessionDisposed)?;
            validate_dispose_state(session.state(), self.reason)?;
            let transition = session
                .apply(SessionAction::Dispose)
                .map_err(DispositionError::Transition)?;
            self.transition = Some(transition);
            self.progress = DispositionProgress::SessionDisposed;
        }

        if self.progress == DispositionProgress::SessionDisposed {
            self.maybe_fail(DispositionProgress::Complete)?;
            let receipt = self.build_receipt()?;
            self.receipt = Some(receipt.clone());
            self.progress = DispositionProgress::Complete;
            return Ok(Some(receipt));
        }

        Ok(None)
    }

    /// Converts a prepared sanitized artifact into bounded in-memory retention.
    ///
    /// # Errors
    ///
    /// Returns a typed path-free error while retaining raw-cleanup progress for retry.
    pub fn retain(
        &mut self,
        session: &mut CustodySession,
    ) -> Result<Option<RetainedSanitization>, DispositionError> {
        if session.session_id().as_str() != self.session_id.as_str() {
            return Err(DispositionError::SessionMismatch);
        }

        let retain_until = matches!(
            &self.kind,
            PreparedKind::Sanitized {
                retention: BoundRetentionDecision {
                    decision: RetentionDecision {
                        mode: RetentionMode::RetainUntil,
                        ..
                    },
                    ..
                },
                ..
            }
        );
        if !retain_until || self.receipt.is_some() {
            return Err(DispositionError::InvalidOperation);
        }

        self.advance_raw_cleanup(session)?;
        if self.progress != DispositionProgress::RootAbsent {
            return Ok(None);
        }

        self.maybe_fail(DispositionProgress::Complete)?;
        if session.state() != SessionState::Sealed {
            return Err(DispositionError::InvalidSessionState);
        }

        session
            .apply(SessionAction::Retain)
            .map_err(DispositionError::Transition)?;

        let PreparedKind::Sanitized {
            artifact,
            receipt,
            retention,
        } = &mut self.kind
        else {
            return Err(DispositionError::InvalidOperation);
        };
        let artifact = artifact
            .take()
            .ok_or(DispositionError::ArtifactUnavailable)?;

        self.progress = DispositionProgress::Complete;

        Ok(Some(RetainedSanitization {
            session_id: self.session_id.clone(),
            artifact: Some(artifact),
            receipt: receipt.clone(),
            retention: retention.clone(),
        }))
    }

    fn advance_raw_cleanup(&mut self, session: &CustodySession) -> Result<(), DispositionError> {
        if self.progress == DispositionProgress::Prepared {
            self.maybe_fail(DispositionProgress::SourceAbsent)?;
            self.staging_mut()?
                .remove_source(session)
                .map_err(map_staging_error)?;
            self.progress = DispositionProgress::SourceAbsent;
        }

        if self.progress == DispositionProgress::SourceAbsent {
            self.maybe_fail(DispositionProgress::LeaseAbsent)?;
            self.staging_mut()?
                .release_lease()
                .map_err(map_staging_error)?;
            self.progress = DispositionProgress::LeaseAbsent;
        }

        if self.progress == DispositionProgress::LeaseAbsent {
            self.maybe_fail(DispositionProgress::RootAbsent)?;
            self.staging_mut()?
                .remove_root()
                .map_err(map_staging_error)?;
            self.staging = None;
            self.progress = DispositionProgress::RootAbsent;
        }

        Ok(())
    }

    fn staging_mut(&mut self) -> Result<&mut DispositionStaging, DispositionError> {
        self.staging
            .as_mut()
            .ok_or(DispositionError::InvalidOperation)
    }

    fn build_receipt(&self) -> Result<LogicalDispositionReceipt, DispositionError> {
        let transition = self
            .transition
            .as_ref()
            .ok_or(DispositionError::InvalidOperation)?;

        let (sanitized_commitment_sha256, retention_decision_sha256) = match &self.kind {
            PreparedKind::Sanitized {
                receipt, retention, ..
            } => (
                Some(receipt.sanitized_commitment_sha256().to_owned()),
                Some(retention.retention_decision_sha256.clone()),
            ),
            PreparedKind::Terminal => (None, None),
        };

        let logical_disposition_sha256 = compute_logical_disposition_sha256(
            &self.session_id,
            transition,
            self.source_commitment_sha256.as_deref(),
            sanitized_commitment_sha256.as_deref(),
            retention_decision_sha256.as_deref(),
            self.reason,
            true,
            true,
            true,
            self.artifact_overwrite_attempted,
            self.deadline_met,
        )?;

        Ok(LogicalDispositionReceipt {
            prior_state: transition.prior_state,
            resulting_state: transition.resulting_state,
            revision: transition.revision,
            transition_sha256: transition.transition_sha256.clone(),
            source_commitment_sha256: self.source_commitment_sha256.clone(),
            sanitized_commitment_sha256,
            retention_decision_sha256,
            disposition_reason: self.reason,
            raw_source_absent: true,
            lease_absent: true,
            staging_root_absent: true,
            sanitized_artifact_overwrite_attempted: self.artifact_overwrite_attempted,
            deadline_met: self.deadline_met,
            logical_disposition_sha256,
        })
    }

    #[cfg(test)]
    fn inject_failure_before(&mut self, stage: DispositionProgress) {
        self.fail_before = Some(stage);
    }

    #[allow(clippy::unnecessary_wraps)]
    fn maybe_fail(&mut self, stage: DispositionProgress) -> Result<(), DispositionError> {
        #[cfg(test)]
        {
            if self.fail_before == Some(stage) {
                self.fail_before = None;
                return Err(DispositionError::InjectedFailure(stage));
            }
        }

        #[cfg(not(test))]
        {
            let _ = (self.progress, stage);
        }

        Ok(())
    }
}

impl fmt::Debug for PreparedDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDisposition")
            .field("session_id", &"[redacted]")
            .field("progress", &self.progress)
            .field("source_commitment_sha256", &"[redacted]")
            .field("reason", &self.reason)
            .field("deadline_met", &self.deadline_met)
            .field(
                "artifact_overwrite_attempted",
                &self.artifact_overwrite_attempted,
            )
            .finish_non_exhaustive()
    }
}

pub struct RetainedSanitization {
    session_id: String,
    artifact: Option<SanitizedArtifact>,
    receipt: SanitizedOutputReceipt,
    retention: BoundRetentionDecision,
}

impl RetainedSanitization {
    #[must_use]
    pub fn retention_decision_sha256(&self) -> &str {
        &self.retention.retention_decision_sha256
    }

    #[must_use]
    pub const fn dispose_by_unix_seconds(&self) -> u64 {
        self.retention.decision.dispose_by_unix_seconds
    }

    #[must_use]
    pub fn sanitized_commitment_sha256(&self) -> &str {
        self.receipt.sanitized_commitment_sha256()
    }

    #[must_use]
    pub fn prepare_disposition(mut self, disposed_at_unix_seconds: u64) -> PreparedDisposition {
        let deadline_met =
            disposed_at_unix_seconds <= self.retention.decision.dispose_by_unix_seconds;
        let source_commitment_sha256 = self.receipt.source_commitment_sha256().to_owned();
        PreparedDisposition {
            session_id: self.session_id,
            progress: DispositionProgress::RootAbsent,
            staging: None,
            kind: PreparedKind::Sanitized {
                artifact: self.artifact.take(),
                receipt: self.receipt,
                retention: self.retention,
            },
            source_commitment_sha256: Some(source_commitment_sha256),
            reason: DispositionReason::RetentionReleased,
            deadline_met: Some(deadline_met),
            artifact_overwrite_attempted: false,
            transition: None,
            receipt: None,
            #[cfg(test)]
            fail_before: None,
        }
    }
}

impl fmt::Debug for RetainedSanitization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedSanitization")
            .field("session_id", &"[redacted]")
            .field("artifact", &"[redacted]")
            .field("sanitized_commitment_sha256", &"[redacted]")
            .field("retention_decision_sha256", &"[redacted]")
            .finish()
    }
}

/// Prepares a sealed sanitized artifact for immediate disposition or bounded retention.
///
/// # Errors
///
/// Returns a typed path-free error unless the session, source commitment, controlled root, lease,
/// source entry, sanitizer receipt, and retention decision form one exact custody plan.
#[allow(
    clippy::large_types_passed_by_value,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments
)]
pub fn prepare_sanitized_disposition(
    parent: &StagingParent,
    session: &CustodySession,
    root: ControlledStagingRoot,
    lease: SessionLease,
    source_name: SourceName,
    source_commitment: SourceCommitmentReceipt,
    sanitization: SanitizationResult,
    retention_decision: RetentionDecision,
) -> Result<PreparedDisposition, DispositionError> {
    if session.state() != SessionState::Sealed {
        return Err(DispositionError::InvalidSessionState);
    }
    if sanitization.receipt().source_commitment_sha256() != source_commitment.commitment_sha256() {
        return Err(DispositionError::SourceVerification);
    }

    let bound_retention =
        bind_retention_decision(session, sanitization.receipt(), retention_decision)?;
    let staging = prepare_disposition_staging(
        parent,
        session,
        root,
        lease,
        Some((source_name, source_commitment.clone())),
    )
    .map_err(map_staging_error)?;
    let source_commitment_sha256 = source_commitment.commitment_sha256().to_owned();
    let (artifact, receipt) = sanitization.into_disposition_parts();

    Ok(PreparedDisposition {
        session_id: session.session_id().as_str().to_owned(),
        progress: DispositionProgress::Prepared,
        staging: Some(staging),
        kind: PreparedKind::Sanitized {
            artifact: Some(artifact),
            receipt,
            retention: bound_retention,
        },
        source_commitment_sha256: Some(source_commitment_sha256),
        reason: DispositionReason::Completed,
        deadline_met: None,
        artifact_overwrite_attempted: false,
        transition: None,
        receipt: None,
        #[cfg(test)]
        fail_before: None,
    })
}

/// Prepares an aborted or expired session for terminal logical disposition.
///
/// `source` is absent only when no staged source was ever committed.
///
/// # Errors
///
/// Returns a typed path-free error unless the terminal-pre-disposal state and controlled staging
/// plan are exact.
#[allow(clippy::large_types_passed_by_value, clippy::needless_pass_by_value)]
pub fn prepare_terminal_disposition(
    parent: &StagingParent,
    session: &CustodySession,
    root: ControlledStagingRoot,
    lease: SessionLease,
    source: Option<(SourceName, SourceCommitmentReceipt)>,
) -> Result<PreparedDisposition, DispositionError> {
    let reason = match session.state() {
        SessionState::Aborted => DispositionReason::Aborted,
        SessionState::Expired => DispositionReason::Expired,
        _ => return Err(DispositionError::InvalidSessionState),
    };
    let source_commitment_sha256 = source
        .as_ref()
        .map(|(_, receipt)| receipt.commitment_sha256().to_owned());
    let staging = prepare_disposition_staging(parent, session, root, lease, source)
        .map_err(map_staging_error)?;

    Ok(PreparedDisposition {
        session_id: session.session_id().as_str().to_owned(),
        progress: DispositionProgress::Prepared,
        staging: Some(staging),
        kind: PreparedKind::Terminal,
        source_commitment_sha256,
        reason,
        deadline_met: None,
        artifact_overwrite_attempted: false,
        transition: None,
        receipt: None,
        #[cfg(test)]
        fail_before: None,
    })
}

fn bind_retention_decision(
    session: &CustodySession,
    receipt: &SanitizedOutputReceipt,
    decision: RetentionDecision,
) -> Result<BoundRetentionDecision, DispositionError> {
    let retention_decision_sha256 = compute_retention_decision_sha256(session, receipt, &decision)?;
    Ok(BoundRetentionDecision {
        decision,
        retention_decision_sha256,
    })
}

fn compute_retention_decision_sha256(
    session: &CustodySession,
    receipt: &SanitizedOutputReceipt,
    decision: &RetentionDecision,
) -> Result<String, DispositionError> {
    let mut digest = Sha256::new();
    digest.update(RETENTION_DECISION_DOMAIN);
    update_field(&mut digest, session.session_id().as_str())?;
    update_field(&mut digest, receipt.source_commitment_sha256())?;
    update_field(&mut digest, receipt.sanitized_commitment_sha256())?;
    update_field(&mut digest, receipt.profile_id().as_str())?;
    update_field(&mut digest, &receipt.profile_version().to_string())?;
    update_field(&mut digest, receipt.output_class().as_str())?;
    update_field(&mut digest, decision.mode.as_str())?;
    update_field(&mut digest, decision.owner.as_str())?;
    update_field(&mut digest, &decision.justification_sha256)?;
    update_field(&mut digest, &decision.decided_at_unix_seconds.to_string())?;
    update_field(&mut digest, &decision.dispose_by_unix_seconds.to_string())?;
    update_field(&mut digest, &decision.retention_window_seconds.to_string())?;
    Ok(encode_lower_hex(digest.finalize().as_ref()))
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn compute_logical_disposition_sha256(
    session_id: &str,
    transition: &SessionTransitionReceipt,
    source_commitment_sha256: Option<&str>,
    sanitized_commitment_sha256: Option<&str>,
    retention_decision_sha256: Option<&str>,
    reason: DispositionReason,
    raw_source_absent: bool,
    lease_absent: bool,
    staging_root_absent: bool,
    sanitized_artifact_overwrite_attempted: bool,
    deadline_met: Option<bool>,
) -> Result<String, DispositionError> {
    let mut digest = Sha256::new();
    digest.update(LOGICAL_DISPOSITION_DOMAIN);
    update_field(&mut digest, session_id)?;
    update_field(&mut digest, transition.prior_state.as_str())?;
    update_field(&mut digest, transition.resulting_state.as_str())?;
    update_field(&mut digest, &transition.revision.to_string())?;
    update_field(&mut digest, &transition.transition_sha256)?;
    update_field(
        &mut digest,
        source_commitment_sha256.unwrap_or(ABSENT_MARKER),
    )?;
    update_field(
        &mut digest,
        sanitized_commitment_sha256.unwrap_or(ABSENT_MARKER),
    )?;
    update_field(
        &mut digest,
        retention_decision_sha256.unwrap_or(ABSENT_MARKER),
    )?;
    update_field(&mut digest, reason.as_str())?;
    update_field(&mut digest, bool_text(raw_source_absent))?;
    update_field(&mut digest, bool_text(lease_absent))?;
    update_field(&mut digest, bool_text(staging_root_absent))?;
    update_field(
        &mut digest,
        bool_text(sanitized_artifact_overwrite_attempted),
    )?;
    update_field(
        &mut digest,
        deadline_met.map_or(NOT_APPLICABLE_MARKER, bool_text),
    )?;
    Ok(encode_lower_hex(digest.finalize().as_ref()))
}

fn update_field(digest: &mut Sha256, value: &str) -> Result<(), DispositionError> {
    let length = u64::try_from(value.len()).map_err(|_| DispositionError::CapacityOverflow)?;
    digest.update(length.to_be_bytes());
    digest.update(value.as_bytes());
    Ok(())
}

const fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn validate_justification(value: &str) -> Result<(), RetentionDecisionError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(RetentionDecisionError::InvalidJustification)
    }
}

fn validate_dispose_state(
    state: SessionState,
    reason: DispositionReason,
) -> Result<(), DispositionError> {
    let valid = matches!(
        (state, reason),
        (SessionState::Sealed, DispositionReason::Completed)
            | (SessionState::Retained, DispositionReason::RetentionReleased)
            | (SessionState::Aborted, DispositionReason::Aborted)
            | (SessionState::Expired, DispositionReason::Expired)
    );
    if valid {
        Ok(())
    } else {
        Err(DispositionError::InvalidSessionState)
    }
}

fn map_staging_error(error: DispositionStagingError) -> DispositionError {
    match error {
        DispositionStagingError::InvalidState => DispositionError::InvalidSessionState,
        DispositionStagingError::SessionMismatch => DispositionError::SessionMismatch,
        DispositionStagingError::SourceVerification => DispositionError::SourceVerification,
        DispositionStagingError::UnexpectedEntry => DispositionError::UnexpectedStagingEntry,
        DispositionStagingError::SourceRemoval => DispositionError::SourceRemoval,
        DispositionStagingError::LeaseRelease => DispositionError::LeaseRelease,
        DispositionStagingError::RootRemoval => DispositionError::RootRemoval,
    }
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

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    use crate::sanitizer_profile::SanitizerProfileId;
    use crate::session::SessionId;
    use crate::source::SourceReadLimit;
    use crate::staging::{
        commit_controlled_synthetic_source, sanitize_controlled_synthetic_source,
    };
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
    const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
    const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";
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
                    "systeme-local-disposition-unit-{}-{nonce}",
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
                "unable to allocate disposition unit-test parent",
            ))
        }

        fn staging_path(&self) -> PathBuf {
            self.path.join("stg_0123456789abcdef0123456789abcdef")
        }
    }

    impl Drop for TempParent {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn prepared_immediate()
    -> Result<(TempParent, CustodySession, PreparedDisposition), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let mut session = CustodySession::new(SessionId::from_str(SESSION)?);
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
        fs::write(temp.staging_path().join(SOURCE), UI_EXPORT)?;
        session.apply(SessionAction::BeginCollection)?;
        let source_name = SourceName::from_str(SOURCE)?;
        let source_commitment = commit_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &source_name,
            SourceReadLimit::new(512)?,
        )?;
        let sanitization = sanitize_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &source_name,
            &source_commitment,
            SanitizerProfileId::UiExportV1,
        )?;
        session.apply(SessionAction::Seal)?;
        let decision = RetentionDecision::dispose_immediately(DIGEST, 100)?;
        let prepared = prepare_sanitized_disposition(
            &parent,
            &session,
            root,
            lease,
            source_name,
            source_commitment,
            sanitization,
            decision,
        )?;
        Ok((temp, session, prepared))
    }

    #[test]
    fn deterministic_failures_are_retryable_at_every_progress_boundary()
    -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                DispositionProgress::SourceAbsent,
                DispositionProgress::Prepared,
            ),
            (
                DispositionProgress::LeaseAbsent,
                DispositionProgress::SourceAbsent,
            ),
            (
                DispositionProgress::RootAbsent,
                DispositionProgress::LeaseAbsent,
            ),
            (
                DispositionProgress::ArtifactOverwritten,
                DispositionProgress::RootAbsent,
            ),
            (
                DispositionProgress::SessionDisposed,
                DispositionProgress::ArtifactOverwritten,
            ),
            (
                DispositionProgress::Complete,
                DispositionProgress::SessionDisposed,
            ),
        ];

        for (failure_stage, expected_progress) in cases {
            let (_temp, mut session, mut prepared) = prepared_immediate()?;
            prepared.inject_failure_before(failure_stage);

            assert_eq!(
                prepared.dispose(&mut session),
                Err(DispositionError::InjectedFailure(failure_stage))
            );
            assert_eq!(prepared.progress(), expected_progress);

            let receipt = prepared
                .dispose(&mut session)?
                .ok_or_else(|| io::Error::other("retry did not complete"))?;
            assert_eq!(prepared.progress(), DispositionProgress::Complete);
            assert_eq!(session.state(), SessionState::Disposed);
            assert_eq!(receipt.resulting_state(), SessionState::Disposed);
        }

        Ok(())
    }

    #[test]
    fn retention_windows_are_closed_and_bounded() {
        assert!(RetentionDecision::dispose_immediately(DIGEST, 42).is_ok());
        assert!(RetentionDecision::retain_until(DIGEST, 42, 43).is_ok());
        assert!(RetentionDecision::retain_until(DIGEST, 42, 942).is_ok());
        assert!(matches!(
            RetentionDecision::retain_until(DIGEST, 42, 42),
            Err(RetentionDecisionError::InvalidWindow)
        ));
        assert!(matches!(
            RetentionDecision::retain_until(DIGEST, 42, 943),
            Err(RetentionDecisionError::InvalidWindow)
        ));
        assert!(matches!(
            RetentionDecision::dispose_immediately("ABC", 42),
            Err(RetentionDecisionError::InvalidJustification)
        ));
    }

    #[test]
    fn domains_are_exact_and_separate() {
        assert_eq!(
            RETENTION_DECISION_DOMAIN,
            b"systeme-local:operator-evidence-retention-decision:v1\0"
        );
        assert_eq!(
            LOGICAL_DISPOSITION_DOMAIN,
            b"systeme-local:operator-evidence-logical-disposition:v1\0"
        );
        assert_ne!(RETENTION_DECISION_DOMAIN, LOGICAL_DISPOSITION_DOMAIN);
    }

    #[test]
    fn debug_output_is_secret_free() -> Result<(), RetentionDecisionError> {
        let decision = RetentionDecision::retain_until(DIGEST, 10, 20)?;
        let rendered = format!("{decision:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains(DIGEST));
        Ok(())
    }

    fn sanitized_receipt_for_commitment()
    -> Result<(CustodySession, SanitizedOutputReceipt), Box<dyn Error>> {
        let mut session = CustodySession::new(SessionId::from_str(SESSION)?);
        session.apply(SessionAction::BeginCollection)?;
        let source = crate::source::GuardedSource::from_test_bytes(UI_EXPORT);
        let source_commitment = crate::commitment::commit_guarded_source(&session, &source)?;
        let sanitization = crate::sanitizer::sanitize_guarded_source(
            &session,
            &source,
            &source_commitment,
            SanitizerProfileId::UiExportV1,
        )?;
        let receipt = sanitization.receipt().clone();
        session.apply(SessionAction::Seal)?;
        Ok((session, receipt))
    }

    #[test]
    fn retention_commitment_binds_closed_decision_fields() -> Result<(), Box<dyn Error>> {
        let (session, receipt) = sanitized_receipt_for_commitment()?;
        let baseline_decision = RetentionDecision::retain_until(DIGEST, 100, 200)?;
        let baseline = compute_retention_decision_sha256(&session, &receipt, &baseline_decision)?;

        let other_justification =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for decision in [
            RetentionDecision::dispose_immediately(DIGEST, 100)?,
            RetentionDecision::retain_until(other_justification, 100, 200)?,
            RetentionDecision::retain_until(DIGEST, 101, 200)?,
            RetentionDecision::retain_until(DIGEST, 100, 201)?,
        ] {
            assert_ne!(
                compute_retention_decision_sha256(&session, &receipt, &decision)?,
                baseline
            );
        }

        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn logical_disposition_commitment_binds_every_receipt_class() -> Result<(), DispositionError> {
        let transition = SessionTransitionReceipt {
            session_id: SessionId::from_str(SESSION)
                .map_err(|_| DispositionError::InvalidOperation)?,
            prior_state: SessionState::Sealed,
            action: SessionAction::Dispose,
            resulting_state: SessionState::Disposed,
            revision: 3,
            transition_sha256: DIGEST.to_owned(),
        };
        let baseline = compute_logical_disposition_sha256(
            SESSION,
            &transition,
            Some(DIGEST),
            Some(DIGEST),
            Some(DIGEST),
            DispositionReason::Completed,
            true,
            true,
            true,
            true,
            None,
        )?;

        let other_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let variants = [
            compute_logical_disposition_sha256(
                "ses_fedcba9876543210fedcba9876543210",
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &SessionTransitionReceipt {
                    prior_state: SessionState::Retained,
                    ..transition.clone()
                },
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &SessionTransitionReceipt {
                    revision: 4,
                    ..transition.clone()
                },
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &SessionTransitionReceipt {
                    transition_sha256: other_digest.to_owned(),
                    ..transition.clone()
                },
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                None,
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(other_digest),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                None,
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Expired,
                true,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                false,
                true,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                false,
                true,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                false,
                true,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                false,
                None,
            )?,
            compute_logical_disposition_sha256(
                SESSION,
                &transition,
                Some(DIGEST),
                Some(DIGEST),
                Some(DIGEST),
                DispositionReason::Completed,
                true,
                true,
                true,
                true,
                Some(false),
            )?,
        ];

        for variant in variants {
            assert_ne!(variant, baseline);
        }

        Ok(())
    }
}
