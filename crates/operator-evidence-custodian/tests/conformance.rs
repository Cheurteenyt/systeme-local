use serde::Deserialize;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use systeme_local_operator_evidence_custodian::{
    ContractRequest, ContractSuccessResponse, ProtocolErrorCode, parse_request_text,
    process_input_bytes,
};

#[derive(Debug, Deserialize)]
struct InvalidCase {
    name: String,
    input: String,
    error_code: ProtocolErrorCode,
    forbidden_echo: Option<String>,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests")
        .join("fixtures")
        .join("operator_evidence_custodian")
        .join(name)
}

fn fixture(name: &str) -> Result<String, Box<dyn Error>> {
    let content = fs::read_to_string(fixture_path(name))?;
    Ok(content)
}

#[test]
fn valid_fixture_produces_the_exact_response() -> Result<(), Box<dyn Error>> {
    let request_text = fixture("valid_request.ndjson")?;
    let expected_response = fixture("valid_response.ndjson")?;

    let request: ContractRequest = parse_request_text(&request_text)?;
    assert_eq!(request.protocol_version, 1);
    assert_eq!(request.request_id, "contract_probe_001");

    let processed = process_input_bytes(request_text.as_bytes());
    assert_eq!(processed.exit_code, 0);
    assert_eq!(processed.stdout, expected_response);
    Ok(())
}

#[test]
fn invalid_fixtures_fail_closed_with_typed_codes() -> Result<(), Box<dyn Error>> {
    let cases: Vec<InvalidCase> = serde_json::from_str(&fixture("invalid_cases.json")?)?;

    for case in cases {
        let processed = process_input_bytes(case.input.as_bytes());
        assert!(!case.name.is_empty());
        assert_eq!(processed.exit_code, 2);

        let response: Value = serde_json::from_str(processed.stdout.trim_end())?;
        let expected_code = serde_json::to_value(case.error_code)?;
        assert_eq!(response.get("error_code"), Some(&expected_code));

        if let Some(forbidden) = case.forbidden_echo {
            assert!(!processed.stdout.contains(&forbidden));
        }
    }
    Ok(())
}

#[test]
fn success_response_contains_no_path_or_secret_fields() -> Result<(), Box<dyn Error>> {
    let processed = process_input_bytes(fixture("valid_request.ndjson")?.as_bytes());
    assert_eq!(processed.exit_code, 0);

    for forbidden in [
        "source_path",
        "raw_evidence",
        "credential",
        "secret",
        "token",
        "endpoint",
    ] {
        assert!(!processed.stdout.contains(forbidden));
    }
    Ok(())
}

#[test]
fn descriptor_flags_are_literal_contract_invariants() -> Result<(), Box<dyn Error>> {
    let response = fixture("valid_response.ndjson")?;

    for (expected, invalid) in [
        ("\"synthetic_only\":true", "\"synthetic_only\":false"),
        (
            "\"real_evidence_ingestion\":false",
            "\"real_evidence_ingestion\":true",
        ),
        ("\"filesystem_access\":false", "\"filesystem_access\":true"),
        ("\"network_access\":false", "\"network_access\":true"),
        (
            "\"sanitizer_execution\":false",
            "\"sanitizer_execution\":true",
        ),
        (
            "\"public_provider_model_authority\":false",
            "\"public_provider_model_authority\":true",
        ),
    ] {
        let inverted = response.replace(expected, invalid);
        assert_ne!(inverted, response);
        assert!(serde_json::from_str::<ContractSuccessResponse>(&inverted).is_err());
    }

    Ok(())
}
