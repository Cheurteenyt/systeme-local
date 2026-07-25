mod commitment;
mod disposition;
mod error;
mod protocol;
mod sanitizer;
mod sanitizer_profile;
mod session;
mod source;
mod staging;

pub use commitment::{SourceCommitmentError, SourceCommitmentReceipt};
pub use disposition::{
    DispositionError, DispositionProgress, DispositionReason, LogicalDispositionReceipt,
    PreparedDisposition, RetainedSanitization, RetentionDecision, RetentionDecisionError,
    RetentionMode, RetentionOwner, prepare_sanitized_disposition, prepare_terminal_disposition,
};
pub use error::{Code as ProtocolErrorCode, Error as ProtocolError};
pub use protocol::{
    Descriptor as ContractDescriptor, Failure as ContractErrorResponse, MAX_INPUT_BYTES,
    Operation as ContractOperation, Processed as ProcessedOutput, Request as ContractRequest,
    Status as ContractStatus, Success as ContractSuccessResponse,
    build_success as build_contract_success_response, compute_contract_sha256, parse_request_text,
    process_input_bytes,
};
pub use sanitizer::{
    SanitizationError, SanitizationResult, SanitizedArtifact, SanitizedOutputReceipt,
};
pub use sanitizer_profile::{
    SanitizedOutputClass, SanitizerEvidenceClass, SanitizerProfileDescriptor,
    SanitizerProfileError, SanitizerProfileId, SanitizerProfileIdError, sanitizer_profile,
    sanitizer_profiles, validate_sanitizer_profiles,
};
pub use session::{
    CustodySession, SessionAction, SessionId, SessionIdError, SessionState,
    SessionTransitionReceipt, TransitionError, compute_transition_sha256,
};
pub use source::{
    GuardedSource, MAX_SYNTHETIC_SOURCE_BYTES, SOURCE_READ_CHUNK_BYTES, SourceName,
    SourceNameError, SourceReadError, SourceReadLimit, SourceReadLimitError, StagingRoot,
    read_synthetic_source,
};

pub use staging::{
    ControlledCommitmentError, ControlledReadError, ControlledSanitizationError,
    ControlledStagingRoot, SessionLease, StagingError, StagingParent,
    commit_controlled_synthetic_source, read_controlled_synthetic_source,
    sanitize_controlled_synthetic_source,
};
