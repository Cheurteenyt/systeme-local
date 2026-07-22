use std::error::Error;
use std::str::FromStr;
use systeme_local_operator_evidence_custodian::{
    MAX_SYNTHETIC_SOURCE_BYTES, SanitizedOutputClass, SanitizerEvidenceClass, SanitizerProfileId,
    sanitizer_profile, sanitizer_profiles, validate_sanitizer_profiles,
};

#[test]
fn registry_membership_order_and_versions_are_exact() -> Result<(), Box<dyn Error>> {
    validate_sanitizer_profiles()?;

    let expected = [
        (
            SanitizerProfileId::UiExportV1,
            "ui_export_v1",
            SanitizerEvidenceClass::UiExport,
            SanitizedOutputClass::CanonicalUtf8Text,
        ),
        (
            SanitizerProfileId::MetadataDocumentV1,
            "metadata_document_v1",
            SanitizerEvidenceClass::MetadataDocument,
            SanitizedOutputClass::CanonicalJson,
        ),
        (
            SanitizerProfileId::ToolScanSnapshotV1,
            "tool_scan_snapshot_v1",
            SanitizerEvidenceClass::ToolScanSnapshot,
            SanitizedOutputClass::CanonicalJson,
        ),
        (
            SanitizerProfileId::ActionReviewSnapshotV1,
            "action_review_snapshot_v1",
            SanitizerEvidenceClass::ActionReviewSnapshot,
            SanitizedOutputClass::CanonicalJson,
        ),
        (
            SanitizerProfileId::LocalPolicySnapshotV1,
            "local_policy_snapshot_v1",
            SanitizerEvidenceClass::LocalPolicySnapshot,
            SanitizedOutputClass::CanonicalUtf8Text,
        ),
    ];

    assert_eq!(sanitizer_profiles().len(), expected.len());

    for (descriptor, (profile_id, text, input, output)) in sanitizer_profiles().iter().zip(expected)
    {
        assert_eq!(descriptor.profile_id(), profile_id);
        assert_eq!(profile_id.as_str(), text);
        assert_eq!(SanitizerProfileId::from_str(text)?, profile_id);
        assert_eq!(descriptor.profile_version(), 1);
        assert_eq!(descriptor.input_class(), input);
        assert_eq!(descriptor.output_class(), output);
        assert_eq!(descriptor.structured_output(), output.is_structured());
        assert_eq!(sanitizer_profile(profile_id), descriptor);
    }

    Ok(())
}

#[test]
fn profile_limits_and_capability_prohibitions_are_exact() -> Result<(), Box<dyn Error>> {
    validate_sanitizer_profiles()?;

    for descriptor in sanitizer_profiles() {
        assert!(descriptor.max_input_bytes() > 0);
        assert!(descriptor.max_output_bytes() > 0);
        assert!(descriptor.max_input_bytes() <= MAX_SYNTHETIC_SOURCE_BYTES);
        assert!(descriptor.max_output_bytes() <= descriptor.max_input_bytes());
        assert!(descriptor.deterministic_output());
        assert!(!descriptor.network_access());
        assert!(!descriptor.secret_environment_input());
    }

    assert_eq!(
        sanitizer_profile(SanitizerProfileId::UiExportV1).max_input_bytes(),
        MAX_SYNTHETIC_SOURCE_BYTES
    );
    Ok(())
}

#[test]
fn unknown_and_malformed_identifiers_fail_closed() {
    for invalid in [
        "",
        "ui_export",
        "ui_export_v2",
        "UI_EXPORT_V1",
        "metadata_document_v01",
        "tool_scan_snapshot_v1/child",
        "../local_policy_snapshot_v1",
        "sanitized_ui_export_digest",
        "operator_attestation",
    ] {
        assert!(SanitizerProfileId::from_str(invalid).is_err());
    }
}

#[test]
fn profile_contract_is_redacted_pure_and_not_protocol_reachable() {
    let profile = sanitizer_profile(SanitizerProfileId::MetadataDocumentV1);
    let rendered = format!("{profile:?}");
    assert_eq!(rendered, "SanitizerProfileDescriptor([bounded])");
    assert_eq!(
        format!("{:?}", SanitizerProfileId::MetadataDocumentV1),
        "SanitizerProfileId([closed])"
    );
    assert_eq!(
        format!("{:?}", SanitizerEvidenceClass::MetadataDocument),
        "SanitizerEvidenceClass([closed])"
    );
    assert_eq!(
        format!("{:?}", SanitizedOutputClass::CanonicalJson),
        "SanitizedOutputClass([closed])"
    );

    let module = include_str!("../src/sanitizer_profile.rs");
    let protocol = include_str!("../src/protocol.rs");
    let binary = include_str!("../src/main.rs");

    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "serde_json",
        "std::env",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "readiness",
        "provider",
        "verified",
    ] {
        assert!(!module.contains(forbidden));
    }

    for boundary in [protocol, binary] {
        for forbidden in [
            "SanitizerProfileId",
            "SanitizerProfileDescriptor",
            "sanitizer_profiles",
            "SourceCommitmentReceipt",
        ] {
            assert!(!boundary.contains(forbidden));
        }
    }
}
