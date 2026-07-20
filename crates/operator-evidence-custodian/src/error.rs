use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    InputTooLarge,
    MultipleMessages,
    InvalidJson,
    InvalidShape,
    UnknownField,
    MissingField,
    UnsupportedProtocolVersion,
    InvalidRequestId,
    UnsupportedOperation,
    InvalidDigest,
    SerializationFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: Code,
    pub request_id: Option<String>,
}

impl Error {
    pub(crate) fn new(code: Code, request_id: Option<String>) -> Self {
        Self { code, request_id }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "operator-evidence protocol error: {:?}",
            self.code
        )
    }
}

impl std::error::Error for Error {}
