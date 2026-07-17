#![forbid(unsafe_code)]
#![doc = "Independent, non-secret verification of Système Local audit-anchor witnesses."]

mod digest;
mod error;
mod model;
mod verify;
mod windows;
#[cfg(any(windows, test))]
mod windows_contract;

pub use digest::{Digest, DigestParseError};
pub use error::VerificationError;
pub use model::{
    RollbackDomain, StorageProfile, VerificationReport, VerificationScope, WindowsAclReport,
    WindowsEventWitnessReport, WindowsVerificationReport,
};
pub use verify::{verify_files, verify_project_root};
pub use windows::verify_windows_project_root;
