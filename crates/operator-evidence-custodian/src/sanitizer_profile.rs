use crate::source::MAX_SYNTHETIC_SOURCE_BYTES;
use std::fmt;
use std::str::FromStr;

const PROFILE_VERSION: u8 = 1;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SanitizerProfileId {
    UiExportV1,
    MetadataDocumentV1,
    ToolScanSnapshotV1,
    ActionReviewSnapshotV1,
    LocalPolicySnapshotV1,
}

impl SanitizerProfileId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UiExportV1 => "ui_export_v1",
            Self::MetadataDocumentV1 => "metadata_document_v1",
            Self::ToolScanSnapshotV1 => "tool_scan_snapshot_v1",
            Self::ActionReviewSnapshotV1 => "action_review_snapshot_v1",
            Self::LocalPolicySnapshotV1 => "local_policy_snapshot_v1",
        }
    }
}

impl FromStr for SanitizerProfileId {
    type Err = SanitizerProfileIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ui_export_v1" => Ok(Self::UiExportV1),
            "metadata_document_v1" => Ok(Self::MetadataDocumentV1),
            "tool_scan_snapshot_v1" => Ok(Self::ToolScanSnapshotV1),
            "action_review_snapshot_v1" => Ok(Self::ActionReviewSnapshotV1),
            "local_policy_snapshot_v1" => Ok(Self::LocalPolicySnapshotV1),
            _ => Err(SanitizerProfileIdError),
        }
    }
}

impl fmt::Debug for SanitizerProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SanitizerProfileId([closed])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizerProfileIdError;

impl fmt::Display for SanitizerProfileIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid sanitizer profile identifier")
    }
}

impl std::error::Error for SanitizerProfileIdError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SanitizerEvidenceClass {
    UiExport,
    MetadataDocument,
    ToolScanSnapshot,
    ActionReviewSnapshot,
    LocalPolicySnapshot,
}

impl SanitizerEvidenceClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UiExport => "ui_export",
            Self::MetadataDocument => "metadata_document",
            Self::ToolScanSnapshot => "tool_scan_snapshot",
            Self::ActionReviewSnapshot => "action_review_snapshot",
            Self::LocalPolicySnapshot => "local_policy_snapshot",
        }
    }
}

impl fmt::Debug for SanitizerEvidenceClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SanitizerEvidenceClass([closed])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SanitizedOutputClass {
    CanonicalUtf8Text,
    CanonicalJson,
}

impl SanitizedOutputClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalUtf8Text => "canonical_utf8_text",
            Self::CanonicalJson => "canonical_json",
        }
    }

    #[must_use]
    pub const fn is_structured(self) -> bool {
        matches!(self, Self::CanonicalJson)
    }
}

impl fmt::Debug for SanitizedOutputClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SanitizedOutputClass([closed])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SanitizerProfileDescriptor {
    profile_id: SanitizerProfileId,
    profile_version: u8,
    input_class: SanitizerEvidenceClass,
    output_class: SanitizedOutputClass,
    max_input_bytes: u64,
    max_output_bytes: u64,
    deterministic_output: bool,
    network_access: bool,
    secret_environment_input: bool,
}

impl SanitizerProfileDescriptor {
    #[must_use]
    pub const fn profile_id(self) -> SanitizerProfileId {
        self.profile_id
    }

    #[must_use]
    pub const fn profile_version(self) -> u8 {
        self.profile_version
    }

    #[must_use]
    pub const fn input_class(self) -> SanitizerEvidenceClass {
        self.input_class
    }

    #[must_use]
    pub const fn output_class(self) -> SanitizedOutputClass {
        self.output_class
    }

    #[must_use]
    pub const fn max_input_bytes(self) -> u64 {
        self.max_input_bytes
    }

    #[must_use]
    pub const fn max_output_bytes(self) -> u64 {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn deterministic_output(self) -> bool {
        self.deterministic_output
    }

    #[must_use]
    pub const fn structured_output(self) -> bool {
        self.output_class.is_structured()
    }

    #[must_use]
    pub const fn network_access(self) -> bool {
        self.network_access
    }

    #[must_use]
    pub const fn secret_environment_input(self) -> bool {
        self.secret_environment_input
    }

    fn validate(self) -> Result<(), SanitizerProfileError> {
        if self.profile_version != PROFILE_VERSION
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_input_bytes > MAX_SYNTHETIC_SOURCE_BYTES
            || self.max_output_bytes > self.max_input_bytes
            || !self.deterministic_output
            || self.network_access
            || self.secret_environment_input
        {
            return Err(SanitizerProfileError);
        }

        Ok(())
    }
}

impl fmt::Debug for SanitizerProfileDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SanitizerProfileDescriptor([bounded])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizerProfileError;

impl fmt::Display for SanitizerProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid sanitizer profile descriptor")
    }
}

impl std::error::Error for SanitizerProfileError {}

static SANITIZER_PROFILES: [SanitizerProfileDescriptor; 5] = [
    SanitizerProfileDescriptor {
        profile_id: SanitizerProfileId::UiExportV1,
        profile_version: PROFILE_VERSION,
        input_class: SanitizerEvidenceClass::UiExport,
        output_class: SanitizedOutputClass::CanonicalUtf8Text,
        max_input_bytes: MAX_SYNTHETIC_SOURCE_BYTES,
        max_output_bytes: 256 * 1024,
        deterministic_output: true,
        network_access: false,
        secret_environment_input: false,
    },
    SanitizerProfileDescriptor {
        profile_id: SanitizerProfileId::MetadataDocumentV1,
        profile_version: PROFILE_VERSION,
        input_class: SanitizerEvidenceClass::MetadataDocument,
        output_class: SanitizedOutputClass::CanonicalJson,
        max_input_bytes: 2 * 1024 * 1024,
        max_output_bytes: 256 * 1024,
        deterministic_output: true,
        network_access: false,
        secret_environment_input: false,
    },
    SanitizerProfileDescriptor {
        profile_id: SanitizerProfileId::ToolScanSnapshotV1,
        profile_version: PROFILE_VERSION,
        input_class: SanitizerEvidenceClass::ToolScanSnapshot,
        output_class: SanitizedOutputClass::CanonicalJson,
        max_input_bytes: 4 * 1024 * 1024,
        max_output_bytes: 512 * 1024,
        deterministic_output: true,
        network_access: false,
        secret_environment_input: false,
    },
    SanitizerProfileDescriptor {
        profile_id: SanitizerProfileId::ActionReviewSnapshotV1,
        profile_version: PROFILE_VERSION,
        input_class: SanitizerEvidenceClass::ActionReviewSnapshot,
        output_class: SanitizedOutputClass::CanonicalJson,
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 128 * 1024,
        deterministic_output: true,
        network_access: false,
        secret_environment_input: false,
    },
    SanitizerProfileDescriptor {
        profile_id: SanitizerProfileId::LocalPolicySnapshotV1,
        profile_version: PROFILE_VERSION,
        input_class: SanitizerEvidenceClass::LocalPolicySnapshot,
        output_class: SanitizedOutputClass::CanonicalUtf8Text,
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 256 * 1024,
        deterministic_output: true,
        network_access: false,
        secret_environment_input: false,
    },
];

/// Returns the complete sanitizer-profile registry in stable review order.
#[must_use]
pub const fn sanitizer_profiles() -> &'static [SanitizerProfileDescriptor; 5] {
    &SANITIZER_PROFILES
}

/// Returns the fixed descriptor for one closed profile identifier.
#[must_use]
pub const fn sanitizer_profile(
    profile_id: SanitizerProfileId,
) -> &'static SanitizerProfileDescriptor {
    match profile_id {
        SanitizerProfileId::UiExportV1 => &SANITIZER_PROFILES[0],
        SanitizerProfileId::MetadataDocumentV1 => &SANITIZER_PROFILES[1],
        SanitizerProfileId::ToolScanSnapshotV1 => &SANITIZER_PROFILES[2],
        SanitizerProfileId::ActionReviewSnapshotV1 => &SANITIZER_PROFILES[3],
        SanitizerProfileId::LocalPolicySnapshotV1 => &SANITIZER_PROFILES[4],
    }
}

/// Validates the complete closed sanitizer-profile registry.
///
/// # Errors
///
/// Returns a generic fail-closed error if any fixed descriptor violates its
/// version, size or capability invariants.
pub fn validate_sanitizer_profiles() -> Result<(), SanitizerProfileError> {
    for descriptor in &SANITIZER_PROFILES {
        (*descriptor).validate()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_descriptors_fail_closed() {
        let mut descriptor = SANITIZER_PROFILES[0];
        descriptor.max_input_bytes = 0;
        assert_eq!(descriptor.validate(), Err(SanitizerProfileError));

        descriptor = SANITIZER_PROFILES[0];
        descriptor.max_input_bytes = MAX_SYNTHETIC_SOURCE_BYTES + 1;
        assert_eq!(descriptor.validate(), Err(SanitizerProfileError));

        descriptor = SANITIZER_PROFILES[0];
        descriptor.max_output_bytes = descriptor.max_input_bytes + 1;
        assert_eq!(descriptor.validate(), Err(SanitizerProfileError));

        descriptor = SANITIZER_PROFILES[0];
        descriptor.network_access = true;
        assert_eq!(descriptor.validate(), Err(SanitizerProfileError));

        descriptor = SANITIZER_PROFILES[0];
        descriptor.secret_environment_input = true;
        assert_eq!(descriptor.validate(), Err(SanitizerProfileError));
    }
}
