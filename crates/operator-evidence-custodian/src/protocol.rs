use crate::error::{Code, Error};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::str;

pub const MAX_INPUT_BYTES: usize = 8_192;
const CONTRACT_DOMAIN: &[u8] = b"systeme-local:operator-evidence-custodian-contract:v1\0";
const REQUIRED_FIELDS: [&str; 4] = [
    "challenge_sha256",
    "operation",
    "protocol_version",
    "request_id",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    DescribeContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u8,
    pub request_id: String,
    pub operation: Operation,
    pub challenge_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequiredTrue;

impl Serialize for RequiredTrue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for RequiredTrue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("expected literal true"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequiredFalse;

impl Serialize for RequiredFalse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for RequiredFalse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Err(serde::de::Error::custom("expected literal false"))
        } else {
            Ok(Self)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    synthetic_only: RequiredTrue,
    real_evidence_ingestion: RequiredFalse,
    filesystem_access: RequiredFalse,
    network_access: RequiredFalse,
    sanitizer_execution: RequiredFalse,
    public_provider_model_authority: RequiredFalse,
}

impl Descriptor {
    #[must_use]
    pub const fn synthetic() -> Self {
        Self {
            synthetic_only: RequiredTrue,
            real_evidence_ingestion: RequiredFalse,
            filesystem_access: RequiredFalse,
            network_access: RequiredFalse,
            sanitizer_execution: RequiredFalse,
            public_provider_model_authority: RequiredFalse,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Success {
    pub protocol_version: u8,
    pub request_id: String,
    pub status: Status,
    pub operation: Operation,
    pub challenge_sha256: String,
    pub contract_sha256: String,
    pub contract: Descriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub protocol_version: u8,
    pub request_id: Option<String>,
    pub status: Status,
    pub error_code: Code,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Processed {
    pub stdout: String,
    pub exit_code: u8,
}

#[must_use]
pub fn process_input_bytes(input: &[u8]) -> Processed {
    if input.len() > MAX_INPUT_BYTES {
        return failure_output(Error::new(Code::InputTooLarge, None));
    }

    let Ok(text) = str::from_utf8(input) else {
        return failure_output(Error::new(Code::InvalidJson, None));
    };

    let request = match parse_request_text(text) {
        Ok(value) => value,
        Err(error) => return failure_output(error),
    };

    let response = build_success(&request);
    match serialize_line(&response) {
        Ok(stdout) => Processed {
            stdout,
            exit_code: 0,
        },
        Err(error) => failure_output(error),
    }
}

/// Parses one bounded NDJSON request.
///
/// # Errors
///
/// Returns a typed fail-closed protocol error when the message is malformed,
/// contains unknown fields, uses an unsupported version or violates identifier
/// and digest syntax.
pub fn parse_request_text(input: &str) -> Result<Request, Error> {
    let line = normalize_single_line(input)?;
    let value: Value =
        serde_json::from_str(line).map_err(|_| Error::new(Code::InvalidJson, None))?;
    let object = value
        .as_object()
        .ok_or_else(|| Error::new(Code::InvalidShape, None))?;
    let request_id = safe_request_id(object.get("request_id"));

    let actual_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let required_fields = REQUIRED_FIELDS.into_iter().collect::<BTreeSet<_>>();

    if actual_fields.difference(&required_fields).next().is_some() {
        return Err(Error::new(Code::UnknownField, request_id));
    }
    if required_fields.difference(&actual_fields).next().is_some() {
        return Err(Error::new(Code::MissingField, request_id));
    }

    match object.get("protocol_version").and_then(Value::as_u64) {
        Some(1) => {}
        _ => return Err(Error::new(Code::UnsupportedProtocolVersion, request_id)),
    }

    let request_id_value = object
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(Code::InvalidRequestId, None))?
        .to_owned();
    if !valid_identifier(&request_id_value) {
        return Err(Error::new(Code::InvalidRequestId, None));
    }

    match object.get("operation").and_then(Value::as_str) {
        Some("describe_contract") => {}
        _ => {
            return Err(Error::new(
                Code::UnsupportedOperation,
                Some(request_id_value.clone()),
            ));
        }
    }

    let challenge = object
        .get("challenge_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(Code::InvalidDigest, Some(request_id_value.clone())))?;
    if !valid_sha256(challenge) {
        return Err(Error::new(
            Code::InvalidDigest,
            Some(request_id_value.clone()),
        ));
    }

    serde_json::from_value(value)
        .map_err(|_| Error::new(Code::InvalidShape, Some(request_id_value)))
}

#[must_use]
pub fn build_success(request: &Request) -> Success {
    Success {
        protocol_version: 1,
        request_id: request.request_id.clone(),
        status: Status::Ok,
        operation: request.operation,
        challenge_sha256: request.challenge_sha256.clone(),
        contract_sha256: compute_contract_sha256(request),
        contract: Descriptor::synthetic(),
    }
}

#[must_use]
pub fn compute_contract_sha256(request: &Request) -> String {
    let mut digest = Sha256::new();
    digest.update(CONTRACT_DOMAIN);
    update_field(&mut digest, request.protocol_version.to_string().as_bytes());
    update_field(&mut digest, request.request_id.as_bytes());
    update_field(&mut digest, b"describe_contract");
    update_field(&mut digest, request.challenge_sha256.as_bytes());
    encode_lower_hex(digest.finalize().as_ref())
}

fn normalize_single_line(input: &str) -> Result<&str, Error> {
    let without_newline = if let Some(value) = input.strip_suffix("\r\n") {
        value
    } else if let Some(value) = input.strip_suffix('\n') {
        value
    } else {
        input
    };

    if without_newline.contains('\r') || without_newline.contains('\n') {
        return Err(Error::new(Code::MultipleMessages, None));
    }
    if without_newline.is_empty() {
        return Err(Error::new(Code::InvalidJson, None));
    }
    Ok(without_newline)
}

fn safe_request_id(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|candidate| valid_identifier(candidate))
        .map(str::to_owned)
}

fn valid_identifier(value: &str) -> bool {
    if !(3..=128).contains(&value.len()) {
        return false;
    }

    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    first.is_ascii_lowercase()
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn serialize_line<T: Serialize>(value: &T) -> Result<String, Error> {
    let mut line =
        serde_json::to_string(value).map_err(|_| Error::new(Code::SerializationFailure, None))?;
    line.push('\n');
    Ok(line)
}

fn failure_output(error: Error) -> Processed {
    let response = Failure {
        protocol_version: 1,
        request_id: error.request_id,
        status: Status::Error,
        error_code: error.code,
    };
    let stdout = match serialize_line(&response) {
        Ok(value) => value,
        Err(_) => concat!(
            "{\"protocol_version\":1,\"request_id\":null,",
            "\"status\":\"error\",",
            "\"error_code\":\"serialization_failure\"}\n"
        )
        .to_owned(),
    };
    Processed {
        stdout,
        exit_code: 2,
    }
}
