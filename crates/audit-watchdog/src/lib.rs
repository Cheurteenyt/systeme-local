#![forbid(unsafe_code)]
#![doc = "Independent, non-secret verification of Système Local audit-anchor witnesses."]

mod digest;
mod error;
mod model;
mod verify;

pub use digest::{Digest, DigestParseError};
pub use error::VerificationError;
pub use model::{RollbackDomain, StorageProfile, VerificationReport, VerificationScope};
pub use verify::{verify_files, verify_project_root};
