use crate::commitment::{SourceCommitmentError, SourceCommitmentReceipt, commit_guarded_source};
use crate::sanitizer_profile::{
    SanitizedOutputClass, SanitizerProfileDescriptor, SanitizerProfileId, sanitizer_profile,
    validate_sanitizer_profiles,
};
use crate::session::{CustodySession, SessionState};
use crate::source::GuardedSource;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};

const SANITIZED_OUTPUT_DOMAIN: &[u8] = b"systeme-local:operator-evidence-sanitized-output:v1\0";
const MAX_CLASSIFIED_ITEMS: u32 = 4_096;

const MAX_JSON_DEPTH: u8 = 1;
#[derive(Clone, Eq, PartialEq)]
pub struct SanitizedOutputReceipt {
    source_commitment_sha256: String,
    profile_id: SanitizerProfileId,
    profile_version: u8,
    output_class: SanitizedOutputClass,
    sanitized_byte_len: u64,
    sanitized_commitment_sha256: String,
}

impl SanitizedOutputReceipt {
    #[must_use]
    pub fn source_commitment_sha256(&self) -> &str {
        &self.source_commitment_sha256
    }

    #[must_use]
    pub const fn profile_id(&self) -> SanitizerProfileId {
        self.profile_id
    }

    #[must_use]
    pub const fn profile_version(&self) -> u8 {
        self.profile_version
    }

    #[must_use]
    pub const fn output_class(&self) -> SanitizedOutputClass {
        self.output_class
    }

    #[must_use]
    pub const fn sanitized_byte_len(&self) -> u64 {
        self.sanitized_byte_len
    }

    #[must_use]
    pub fn sanitized_commitment_sha256(&self) -> &str {
        &self.sanitized_commitment_sha256
    }
}

impl fmt::Debug for SanitizedOutputReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedOutputReceipt")
            .field("source_commitment_sha256", &"[redacted]")
            .field("profile_id", &self.profile_id)
            .field("profile_version", &self.profile_version)
            .field("output_class", &self.output_class)
            .field("sanitized_byte_len", &self.sanitized_byte_len)
            .field("sanitized_commitment_sha256", &"[redacted]")
            .finish()
    }
}

pub struct SanitizedArtifact {
    output_class: SanitizedOutputClass,
    bytes: Vec<u8>,
}

impl SanitizedArtifact {
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub const fn output_class(&self) -> SanitizedOutputClass {
        self.output_class
    }

    pub(crate) fn commitment_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn overwrite_bytes(&mut self) {
        self.bytes.fill(0);
    }

    #[cfg(test)]
    fn zeroize_for_test(&mut self) -> &[u8] {
        self.overwrite_bytes();
        &self.bytes
    }
}

impl fmt::Debug for SanitizedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedArtifact")
            .field("output_class", &self.output_class)
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl Drop for SanitizedArtifact {
    fn drop(&mut self) {
        self.overwrite_bytes();
    }
}

pub struct SanitizationResult {
    artifact: SanitizedArtifact,
    receipt: SanitizedOutputReceipt,
}

impl SanitizationResult {
    #[must_use]
    pub const fn artifact(&self) -> &SanitizedArtifact {
        &self.artifact
    }

    #[must_use]
    pub const fn receipt(&self) -> &SanitizedOutputReceipt {
        &self.receipt
    }
}

impl fmt::Debug for SanitizationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizationResult")
            .field("artifact", &self.artifact)
            .field("receipt", &self.receipt)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SanitizationError {
    SessionNotCollecting,
    InvalidProfile,
    SourceCommitment(SourceCommitmentError),
    SourceCommitmentMismatch,
    InputTooLarge,
    InvalidUtf8,
    InvalidText,
    InvalidJson,
    JsonDepthExceeded,
    NonCanonicalInput,
    InvalidDigest,
    InvalidCount,
    OutputTooLarge,
    CapacityOverflow,
    SerializationFailed,
}

impl fmt::Display for SanitizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionNotCollecting => "custody session is not collecting",
            Self::InvalidProfile => "invalid sanitizer profile",
            Self::SourceCommitment(_) => "source commitment verification failed",
            Self::SourceCommitmentMismatch => "source commitment mismatch",
            Self::InputTooLarge => "sanitizer input exceeds the profile limit",
            Self::InvalidUtf8 => "sanitizer input is not valid UTF-8",
            Self::InvalidText => "sanitizer text input is invalid",
            Self::InvalidJson => "sanitizer JSON input is invalid",
            Self::JsonDepthExceeded => "sanitizer JSON nesting exceeds the profile limit",
            Self::NonCanonicalInput => "sanitizer input encoding is not canonical",
            Self::InvalidDigest => "sanitizer digest input is invalid",
            Self::InvalidCount => "sanitizer count input is invalid",
            Self::OutputTooLarge => "sanitizer output exceeds the profile limit",
            Self::CapacityOverflow => "sanitizer capacity overflow",
            Self::SerializationFailed => "sanitizer output serialization failed",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for SanitizationError {}

struct TextFieldContract {
    key: &'static str,
    values: &'static [&'static str],
}

const UI_EXPORT_FIELDS: &[TextFieldContract] = &[
    TextFieldContract {
        key: "access_control",
        values: &["public", "restricted", "unknown"],
    },
    TextFieldContract {
        key: "action_review",
        values: &["approved", "blocked", "unknown"],
    },
    TextFieldContract {
        key: "app_state",
        values: &["draft", "published", "unknown"],
    },
    TextFieldContract {
        key: "authentication",
        values: &["available", "unavailable", "unknown"],
    },
    TextFieldContract {
        key: "tool_scan",
        values: &["blocked", "passed", "unknown"],
    },
    TextFieldContract {
        key: "transport",
        values: &["available", "unavailable", "unknown"],
    },
];

const LOCAL_POLICY_FIELDS: &[TextFieldContract] = &[
    TextFieldContract {
        key: "approval",
        values: &["not_required", "required"],
    },
    TextFieldContract {
        key: "network",
        values: &["disabled", "enabled"],
    },
    TextFieldContract {
        key: "retention",
        values: &["ephemeral", "retained"],
    },
    TextFieldContract {
        key: "secrets",
        values: &["absent", "present"],
    },
    TextFieldContract {
        key: "workspace",
        values: &["isolated", "shared"],
    },
];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenAuthenticationMethod {
    ClientSecretPost,
    PrivateKeyJwt,
    #[serde(rename = "none")]
    NoClientAuthentication,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MetadataDocument {
    authorization_code: bool,
    document_sha256: String,
    pkce: bool,
    refresh_token: bool,
    token_auth_method: TokenAuthenticationMethod,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolScanSnapshot {
    capability_count: u32,
    destructive_count: u32,
    read_only_count: u32,
    snapshot_sha256: String,
    unknown_count: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActionReviewSnapshot {
    action_count: u32,
    approved_count: u32,
    blocked_count: u32,
    snapshot_sha256: String,
    unknown_count: u32,
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
    failure: Option<SanitizationError>,
}

impl BoundedOutput {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            failure: None,
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), SanitizationError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(SanitizationError::CapacityOverflow)?;

        if next > self.limit {
            return Err(SanitizationError::OutputTooLarge);
        }

        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self.extend(buffer) {
            Ok(()) => Ok(buffer.len()),
            Err(error) => {
                self.failure = Some(error);
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "bounded sanitizer output rejected",
                ))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BoundedOutput {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

pub(crate) fn sanitize_guarded_source(
    session: &CustodySession,
    source: &GuardedSource,
    expected_source_commitment: &SourceCommitmentReceipt,
    profile_id: SanitizerProfileId,
) -> Result<SanitizationResult, SanitizationError> {
    if session.state() != SessionState::Collecting {
        return Err(SanitizationError::SessionNotCollecting);
    }

    validate_sanitizer_profiles().map_err(|_| SanitizationError::InvalidProfile)?;
    let actual_source_commitment =
        commit_guarded_source(session, source).map_err(SanitizationError::SourceCommitment)?;

    if &actual_source_commitment != expected_source_commitment {
        return Err(SanitizationError::SourceCommitmentMismatch);
    }

    let descriptor = *sanitizer_profile(profile_id);
    let input_byte_len =
        u64::try_from(source.byte_len()).map_err(|_| SanitizationError::CapacityOverflow)?;

    if input_byte_len > descriptor.max_input_bytes() {
        return Err(SanitizationError::InputTooLarge);
    }

    let output_limit = usize::try_from(descriptor.max_output_bytes())
        .map_err(|_| SanitizationError::CapacityOverflow)?;
    let sanitized_bytes =
        sanitize_profile_bytes(profile_id, source.sanitizer_bytes(), output_limit)?;
    let sanitized_byte_len =
        u64::try_from(sanitized_bytes.len()).map_err(|_| SanitizationError::CapacityOverflow)?;

    if sanitized_byte_len > descriptor.max_output_bytes() {
        return Err(SanitizationError::OutputTooLarge);
    }

    let artifact = SanitizedArtifact {
        output_class: descriptor.output_class(),
        bytes: sanitized_bytes,
    };
    let sanitized_commitment_sha256 = compute_sanitized_commitment(
        session,
        actual_source_commitment.commitment_sha256(),
        descriptor,
        artifact.commitment_bytes(),
    )?;
    let receipt = SanitizedOutputReceipt {
        source_commitment_sha256: actual_source_commitment.commitment_sha256().to_owned(),
        profile_id: descriptor.profile_id(),
        profile_version: descriptor.profile_version(),
        output_class: descriptor.output_class(),
        sanitized_byte_len,
        sanitized_commitment_sha256,
    };

    Ok(SanitizationResult { artifact, receipt })
}

fn sanitize_profile_bytes(
    profile_id: SanitizerProfileId,
    source: &[u8],
    output_limit: usize,
) -> Result<Vec<u8>, SanitizationError> {
    match profile_id {
        SanitizerProfileId::UiExportV1 => {
            sanitize_closed_text(source, UI_EXPORT_FIELDS, output_limit)
        }
        SanitizerProfileId::MetadataDocumentV1 => sanitize_metadata_document(source, output_limit),
        SanitizerProfileId::ToolScanSnapshotV1 => sanitize_tool_scan_snapshot(source, output_limit),
        SanitizerProfileId::ActionReviewSnapshotV1 => {
            sanitize_action_review_snapshot(source, output_limit)
        }
        SanitizerProfileId::LocalPolicySnapshotV1 => {
            sanitize_closed_text(source, LOCAL_POLICY_FIELDS, output_limit)
        }
    }
}

fn sanitize_closed_text(
    source: &[u8],
    contract: &[TextFieldContract],
    output_limit: usize,
) -> Result<Vec<u8>, SanitizationError> {
    let text = std::str::from_utf8(source).map_err(|_| SanitizationError::InvalidUtf8)?;

    if text.is_empty() || !text.ends_with('\n') || text.chars().any(is_forbidden_text_character) {
        return Err(SanitizationError::InvalidText);
    }

    let body = text
        .strip_suffix('\n')
        .ok_or(SanitizationError::InvalidText)?;

    if body.is_empty() || body.contains("\n\n") {
        return Err(SanitizationError::InvalidText);
    }

    let mut values = vec![None; contract.len()];

    for line in body.split('\n') {
        let Some((key, value)) = line.split_once('=') else {
            return Err(SanitizationError::InvalidText);
        };
        let Some(index) = contract.iter().position(|field| field.key == key) else {
            return Err(SanitizationError::InvalidText);
        };

        if !contract[index].values.contains(&value) || values[index].replace(value).is_some() {
            return Err(SanitizationError::InvalidText);
        }
    }

    if values.iter().any(Option::is_none) {
        return Err(SanitizationError::InvalidText);
    }

    let mut output = BoundedOutput::new(output_limit);

    for (field, value) in contract.iter().zip(values) {
        let value = value.ok_or(SanitizationError::InvalidText)?;
        output.extend(field.key.as_bytes())?;
        output.extend(b"=")?;
        output.extend(value.as_bytes())?;
        output.extend(b"\n")?;
    }

    Ok(output.into_bytes())
}

fn sanitize_metadata_document(
    source: &[u8],
    output_limit: usize,
) -> Result<Vec<u8>, SanitizationError> {
    let value: MetadataDocument = parse_canonical_json(source)?;

    if !is_lower_hex_sha256(&value.document_sha256) {
        return Err(SanitizationError::InvalidDigest);
    }

    serialize_bounded_json(&value, output_limit)
}

fn sanitize_tool_scan_snapshot(
    source: &[u8],
    output_limit: usize,
) -> Result<Vec<u8>, SanitizationError> {
    let value: ToolScanSnapshot = parse_canonical_json(source)?;
    validate_classified_counts(
        value.capability_count,
        value.read_only_count,
        value.destructive_count,
        value.unknown_count,
    )?;

    if !is_lower_hex_sha256(&value.snapshot_sha256) {
        return Err(SanitizationError::InvalidDigest);
    }

    serialize_bounded_json(&value, output_limit)
}

fn sanitize_action_review_snapshot(
    source: &[u8],
    output_limit: usize,
) -> Result<Vec<u8>, SanitizationError> {
    let value: ActionReviewSnapshot = parse_canonical_json(source)?;
    validate_classified_counts(
        value.action_count,
        value.approved_count,
        value.blocked_count,
        value.unknown_count,
    )?;

    if !is_lower_hex_sha256(&value.snapshot_sha256) {
        return Err(SanitizationError::InvalidDigest);
    }

    serialize_bounded_json(&value, output_limit)
}

fn parse_canonical_json<T>(source: &[u8]) -> Result<T, SanitizationError>
where
    T: DeserializeOwned + Serialize,
{
    if source.starts_with(b"\xef\xbb\xbf") || source.contains(&b'\r') || source.ends_with(b"\n") {
        return Err(SanitizationError::NonCanonicalInput);
    }

    std::str::from_utf8(source).map_err(|_| SanitizationError::InvalidUtf8)?;

    validate_json_depth(source)?;

    let value = serde_json::from_slice::<T>(source).map_err(|_| SanitizationError::InvalidJson)?;
    let canonical =
        serde_json::to_vec(&value).map_err(|_| SanitizationError::SerializationFailed)?;

    if canonical != source {
        return Err(SanitizationError::NonCanonicalInput);
    }

    Ok(value)
}

fn validate_json_depth(source: &[u8]) -> Result<(), SanitizationError> {
    let mut depth = 0_u8;
    let mut in_string = false;
    let mut escaped = false;

    for &byte in source {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(SanitizationError::JsonDepthExceeded)?;
                if depth > MAX_JSON_DEPTH {
                    return Err(SanitizationError::JsonDepthExceeded);
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(SanitizationError::InvalidJson)?;
            }
            _ => {}
        }
    }

    if in_string || escaped || depth != 0 {
        return Err(SanitizationError::InvalidJson);
    }

    Ok(())
}

fn serialize_bounded_json<T>(value: &T, output_limit: usize) -> Result<Vec<u8>, SanitizationError>
where
    T: Serialize,
{
    let mut output = BoundedOutput::new(output_limit);

    if serde_json::to_writer(&mut output, value).is_err() {
        return match output.failure {
            Some(error) => Err(error),
            None => Err(SanitizationError::SerializationFailed),
        };
    }

    Ok(output.into_bytes())
}

fn validate_classified_counts(
    total: u32,
    first: u32,
    second: u32,
    third: u32,
) -> Result<(), SanitizationError> {
    if total > MAX_CLASSIFIED_ITEMS {
        return Err(SanitizationError::InvalidCount);
    }

    let classified = first
        .checked_add(second)
        .and_then(|count| count.checked_add(third))
        .ok_or(SanitizationError::InvalidCount)?;

    if classified != total {
        return Err(SanitizationError::InvalidCount);
    }

    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_forbidden_text_character(character: char) -> bool {
    character == '\u{feff}'
        || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        || (character.is_control() && character != '\n')
}

fn compute_sanitized_commitment(
    session: &CustodySession,
    source_commitment_sha256: &str,
    descriptor: SanitizerProfileDescriptor,
    sanitized_bytes: &[u8],
) -> Result<String, SanitizationError> {
    compute_sanitized_commitment_fields(
        session.session_id().as_str(),
        source_commitment_sha256,
        descriptor.profile_id().as_str(),
        descriptor.profile_version(),
        descriptor.output_class().as_str(),
        sanitized_bytes,
    )
}

fn compute_sanitized_commitment_fields(
    session_id: &str,
    source_commitment_sha256: &str,
    profile_id: &str,
    profile_version: u8,
    output_class: &str,
    sanitized_bytes: &[u8],
) -> Result<String, SanitizationError> {
    let profile_version = profile_version.to_string();
    let sanitized_byte_len =
        u64::try_from(sanitized_bytes.len()).map_err(|_| SanitizationError::CapacityOverflow)?;
    let mut digest = Sha256::new();
    digest.update(SANITIZED_OUTPUT_DOMAIN);
    update_field(&mut digest, session_id.as_bytes())?;
    update_field(&mut digest, source_commitment_sha256.as_bytes())?;
    update_field(&mut digest, profile_id.as_bytes())?;
    update_field(&mut digest, profile_version.as_bytes())?;
    update_field(&mut digest, output_class.as_bytes())?;
    digest.update(sanitized_byte_len.to_be_bytes());
    digest.update(sanitized_bytes);
    Ok(encode_lower_hex(digest.finalize().as_ref()))
}

fn update_field(digest: &mut Sha256, value: &[u8]) -> Result<(), SanitizationError> {
    let length = u64::try_from(value.len()).map_err(|_| SanitizationError::CapacityOverflow)?;
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
    use crate::session::{SessionAction, SessionId};
    use std::error::Error;
    use std::str::FromStr;

    const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
    const UI_INPUT: &[u8] = b"transport=available\napp_state=draft\ntool_scan=passed\nauthentication=available\naction_review=approved\naccess_control=restricted\n";
    const UI_OUTPUT: &[u8] = b"access_control=restricted\naction_review=approved\napp_state=draft\nauthentication=available\ntool_scan=passed\ntransport=available\n";
    const METADATA: &[u8] = b"{\"authorization_code\":true,\"document_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"pkce\":true,\"refresh_token\":false,\"token_auth_method\":\"none\"}";
    const TOOL_SCAN: &[u8] = b"{\"capability_count\":3,\"destructive_count\":1,\"read_only_count\":2,\"snapshot_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"unknown_count\":0}";
    const ACTION_REVIEW: &[u8] = b"{\"action_count\":3,\"approved_count\":2,\"blocked_count\":1,\"snapshot_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"unknown_count\":0}";
    const POLICY_INPUT: &[u8] = b"workspace=isolated\nsecrets=absent\nretention=ephemeral\nnetwork=disabled\napproval=required\n";
    const POLICY_OUTPUT: &[u8] = b"approval=required\nnetwork=disabled\nretention=ephemeral\nsecrets=absent\nworkspace=isolated\n";

    fn collecting_session() -> Result<CustodySession, Box<dyn Error>> {
        let mut session = CustodySession::new(SessionId::from_str(SESSION)?);
        session.apply(SessionAction::BeginCollection)?;
        Ok(session)
    }

    #[test]
    fn all_profiles_produce_exact_canonical_outputs() -> Result<(), Box<dyn Error>> {
        let fixtures = [
            (SanitizerProfileId::UiExportV1, UI_INPUT, UI_OUTPUT),
            (SanitizerProfileId::MetadataDocumentV1, METADATA, METADATA),
            (SanitizerProfileId::ToolScanSnapshotV1, TOOL_SCAN, TOOL_SCAN),
            (
                SanitizerProfileId::ActionReviewSnapshotV1,
                ACTION_REVIEW,
                ACTION_REVIEW,
            ),
            (
                SanitizerProfileId::LocalPolicySnapshotV1,
                POLICY_INPUT,
                POLICY_OUTPUT,
            ),
        ];

        for (profile_id, input, expected) in fixtures {
            let descriptor = sanitizer_profile(profile_id);
            let limit = usize::try_from(descriptor.max_output_bytes())?;
            assert_eq!(sanitize_profile_bytes(profile_id, input, limit)?, expected);
        }

        Ok(())
    }

    #[test]
    fn sanitized_output_domain_and_framing_are_exact() -> Result<(), Box<dyn Error>> {
        let session = collecting_session()?;
        let descriptor = *sanitizer_profile(SanitizerProfileId::UiExportV1);
        let commitment = compute_sanitized_commitment(
            &session,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            descriptor,
            b"access_control=restricted\n",
        )?;

        assert_eq!(
            SANITIZED_OUTPUT_DOMAIN,
            b"systeme-local:operator-evidence-sanitized-output:v1\0"
        );
        assert_eq!(
            commitment,
            "1909042d7784b4c1215784eaae3ff71756e7bdd90502664c0c5a3a56ea9d2322"
        );
        Ok(())
    }

    #[test]
    fn every_framed_field_and_output_byte_changes_the_commitment() -> Result<(), Box<dyn Error>> {
        let source_commitment = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let baseline = compute_sanitized_commitment_fields(
            SESSION,
            source_commitment,
            "ui_export_v1",
            1,
            "canonical_utf8_text",
            b"abc",
        )?;
        let variants = [
            compute_sanitized_commitment_fields(
                "ses_fedcba9876543210fedcba9876543210",
                source_commitment,
                "ui_export_v1",
                1,
                "canonical_utf8_text",
                b"abc",
            )?,
            compute_sanitized_commitment_fields(
                SESSION,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "ui_export_v1",
                1,
                "canonical_utf8_text",
                b"abc",
            )?,
            compute_sanitized_commitment_fields(
                SESSION,
                source_commitment,
                "metadata_document_v1",
                1,
                "canonical_utf8_text",
                b"abc",
            )?,
            compute_sanitized_commitment_fields(
                SESSION,
                source_commitment,
                "ui_export_v1",
                2,
                "canonical_utf8_text",
                b"abc",
            )?,
            compute_sanitized_commitment_fields(
                SESSION,
                source_commitment,
                "ui_export_v1",
                1,
                "canonical_json",
                b"abc",
            )?,
            compute_sanitized_commitment_fields(
                SESSION,
                source_commitment,
                "ui_export_v1",
                1,
                "canonical_utf8_text",
                b"abcd",
            )?,
        ];

        for variant in variants {
            assert_ne!(variant, baseline);
        }

        for index in 0..3 {
            let mut changed = b"abc".to_vec();
            changed[index] = b'x';
            assert_ne!(
                compute_sanitized_commitment_fields(
                    SESSION,
                    source_commitment,
                    "ui_export_v1",
                    1,
                    "canonical_utf8_text",
                    &changed,
                )?,
                baseline
            );
        }

        Ok(())
    }

    #[test]
    fn malformed_duplicate_unknown_and_noncanonical_inputs_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let ui_limit =
            usize::try_from(sanitizer_profile(SanitizerProfileId::UiExportV1).max_output_bytes())?;
        let json_limit = usize::try_from(
            sanitizer_profile(SanitizerProfileId::MetadataDocumentV1).max_output_bytes(),
        )?;

        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::UiExportV1,
                b"access_control=restricted\naccess_control=public\n",
                ui_limit,
            ),
            Err(SanitizationError::InvalidText)
        );
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::UiExportV1,
                b"endpoint=https://example.invalid\n",
                ui_limit,
            ),
            Err(SanitizationError::InvalidText)
        );
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::UiExportV1,
                b"access_control=restricted\r\n",
                ui_limit,
            ),
            Err(SanitizationError::InvalidText)
        );
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::MetadataDocumentV1,
                b"{\"authorization_code\":true,\"authorization_code\":false,\"document_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"pkce\":true,\"refresh_token\":false,\"token_auth_method\":\"none\"}",
                json_limit,
            ),
            Err(SanitizationError::InvalidJson)
        );
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::MetadataDocumentV1,
                b"{ \"authorization_code\":true,\"document_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"pkce\":true,\"refresh_token\":false,\"token_auth_method\":\"none\"}",
                json_limit,
            ),
            Err(SanitizationError::NonCanonicalInput)
        );
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::MetadataDocumentV1,
                b"{\"authorization_code\":true,\"document_sha256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"pkce\":true,\"refresh_token\":false,\"token_auth_method\":\"none\"}",
                json_limit,
            ),
            Err(SanitizationError::InvalidDigest)
        );
        let tool_limit = usize::try_from(
            sanitizer_profile(SanitizerProfileId::ToolScanSnapshotV1).max_output_bytes(),
        )?;
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::ToolScanSnapshotV1,
                b"{\"capability_count\":3,\"destructive_count\":1,\"read_only_count\":1,\"snapshot_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"unknown_count\":0}",
                tool_limit,
            ),
            Err(SanitizationError::InvalidCount)
        );
        Ok(())
    }

    #[test]
    fn source_commitment_mismatch_precedes_invalid_sanitizer_input() -> Result<(), Box<dyn Error>> {
        let session = collecting_session()?;
        let committed = GuardedSource::from_test_bytes(b"committed");
        let malformed = GuardedSource::from_test_bytes(b"not-a-closed-ui-export");
        let receipt = commit_guarded_source(&session, &committed)?;

        assert!(matches!(
            sanitize_guarded_source(
                &session,
                &malformed,
                &receipt,
                SanitizerProfileId::UiExportV1,
            ),
            Err(SanitizationError::SourceCommitmentMismatch)
        ));
        Ok(())
    }

    #[test]
    fn zero_exact_and_one_byte_over_profile_input_limits_are_distinguished()
    -> Result<(), Box<dyn Error>> {
        let session = collecting_session()?;
        let profile_id = SanitizerProfileId::ActionReviewSnapshotV1;
        let descriptor = sanitizer_profile(profile_id);
        let exact_len = usize::try_from(descriptor.max_input_bytes())?;

        for bytes in [Vec::new(), vec![0_u8; exact_len]] {
            let source = GuardedSource::from_test_bytes(&bytes);
            let receipt = commit_guarded_source(&session, &source)?;
            assert!(matches!(
                sanitize_guarded_source(&session, &source, &receipt, profile_id),
                Err(SanitizationError::InvalidJson)
            ));
        }

        let over = vec![0_u8; exact_len + 1];
        let source = GuardedSource::from_test_bytes(&over);
        let receipt = commit_guarded_source(&session, &source)?;
        assert!(matches!(
            sanitize_guarded_source(&session, &source, &receipt, profile_id),
            Err(SanitizationError::InputTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn bounded_output_accepts_exact_limit_and_rejects_the_next_byte() -> Result<(), Box<dyn Error>>
    {
        let mut output = BoundedOutput::new(3);
        output.extend(b"")?;
        output.extend(b"abc")?;
        assert_eq!(output.extend(b"x"), Err(SanitizationError::OutputTooLarge));
        assert_eq!(output.into_bytes(), b"abc");
        Ok(())
    }

    #[test]
    fn invalid_utf8_depth_and_classified_count_overflow_fail_closed() -> Result<(), Box<dyn Error>>
    {
        let metadata_limit = usize::try_from(
            sanitizer_profile(SanitizerProfileId::MetadataDocumentV1).max_output_bytes(),
        )?;
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::MetadataDocumentV1,
                &[0xff],
                metadata_limit,
            ),
            Err(SanitizationError::InvalidUtf8)
        );

        assert_eq!(validate_json_depth(METADATA), Ok(()));
        assert_eq!(
            validate_json_depth(b"{\"nested\":{}}"),
            Err(SanitizationError::JsonDepthExceeded)
        );

        let one_over = MAX_CLASSIFIED_ITEMS + 1;
        let over_limit = format!(
            concat!(
                "{{\"capability_count\":{},",
                "\"destructive_count\":0,",
                "\"read_only_count\":{},",
                "\"snapshot_sha256\":",
                "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                "\"unknown_count\":0}}"
            ),
            one_over, one_over
        );
        let tool_limit = usize::try_from(
            sanitizer_profile(SanitizerProfileId::ToolScanSnapshotV1).max_output_bytes(),
        )?;
        assert_eq!(
            sanitize_profile_bytes(
                SanitizerProfileId::ToolScanSnapshotV1,
                over_limit.as_bytes(),
                tool_limit,
            ),
            Err(SanitizationError::InvalidCount)
        );
        Ok(())
    }

    #[test]
    fn sanitized_artifact_overwrite_on_drop_is_observable_through_private_helper() {
        let mut artifact = SanitizedArtifact {
            output_class: SanitizedOutputClass::CanonicalJson,
            bytes: b"private-sanitized-bytes".to_vec(),
        };

        assert!(artifact.zeroize_for_test().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn public_artifact_and_receipt_render_only_redacted_metadata() -> Result<(), Box<dyn Error>> {
        let session = collecting_session()?;
        let source = GuardedSource::from_test_bytes(UI_OUTPUT);
        let receipt = commit_guarded_source(&session, &source)?;
        let result =
            sanitize_guarded_source(&session, &source, &receipt, SanitizerProfileId::UiExportV1)?;
        let rendered = format!("{result:?}");

        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("access_control"));
        assert!(!rendered.contains(SESSION));
        assert!(!rendered.contains(receipt.commitment_sha256()));
        assert!(!rendered.contains(result.receipt().sanitized_commitment_sha256()));
        Ok(())
    }
}
