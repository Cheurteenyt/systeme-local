use std::fmt;
use std::io;
use std::path::PathBuf;

/// A fail-closed verification failure.
#[derive(Debug)]
pub enum VerificationError {
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// A file is not a regular, direct filesystem object.
    UnsafeFileType {
        /// Affected path.
        path: PathBuf,
    },
    /// A bounded input exceeded its maximum size.
    SizeLimit {
        /// Affected path.
        path: PathBuf,
        /// Maximum accepted bytes.
        limit: u64,
    },
    /// A JSON document could not be decoded.
    Json {
        /// Affected path.
        path: PathBuf,
        /// Optional anchor line number.
        line: Option<usize>,
        /// Decoder message.
        message: String,
    },
    /// The bootstrap receipt violates an invariant.
    Receipt {
        /// Invariant failure.
        message: String,
    },
    /// An anchor checkpoint violates an invariant.
    Checkpoint {
        /// One-based checkpoint line.
        line: usize,
        /// Invariant failure.
        message: String,
    },
    /// The receipt points to a different anchor file.
    AnchorPath {
        /// Path recorded in the receipt.
        recorded: PathBuf,
        /// Path actually verified.
        actual: PathBuf,
    },
}

impl VerificationError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn receipt(message: impl Into<String>) -> Self {
        Self::Receipt {
            message: message.into(),
        }
    }

    pub(crate) fn checkpoint(line: usize, message: impl Into<String>) -> Self {
        Self::Checkpoint {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} failed for {}: {source}",
                path.display()
            ),
            Self::UnsafeFileType { path } => write!(
                formatter,
                "{} must be a regular file and must not be a symbolic link",
                path.display()
            ),
            Self::SizeLimit { path, limit } => write!(
                formatter,
                "{} exceeds the {limit}-byte verification limit",
                path.display()
            ),
            Self::Json {
                path,
                line: Some(line),
                message,
            } => write!(
                formatter,
                "invalid JSON checkpoint at {} line {line}: {message}",
                path.display()
            ),
            Self::Json {
                path,
                line: None,
                message,
            } => write!(
                formatter,
                "invalid JSON document at {}: {message}",
                path.display()
            ),
            Self::Receipt { message } => {
                write!(formatter, "invalid bootstrap receipt: {message}")
            }
            Self::Checkpoint { line, message } => {
                write!(
                    formatter,
                    "invalid anchor checkpoint at line {line}: {message}"
                )
            }
            Self::AnchorPath { recorded, actual } => write!(
                formatter,
                "receipt anchor path {} does not match verified path {}",
                recorded.display(),
                actual.display()
            ),
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
