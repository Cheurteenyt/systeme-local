use crate::session::{CustodySession, SessionId, SessionState};
use crate::source::{
    GuardedSource, SourceName, SourceReadError, SourceReadLimit, StagingRoot, read_synthetic_source,
};
use cap_fs_ext::MetadataExt;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilder, DirBuilderExt as _, OpenOptionsExt as _};
use std::fmt;
use std::fs as std_fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;

const STAGING_NAME_PREFIX: &str = "stg_";
const STAGING_NAME_HEX_LENGTH: usize = 32;
const LEASE_FILE_NAME: &str = ".custody.lock";
const LEASE_MARKER: &[u8] = b"systeme-local:operator-evidence-session-lease:v1\n";
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const READ_CONTROL: u32 = 0x0002_0000;
#[cfg(windows)]
const WRITE_DAC: u32 = 0x0004_0000;

#[derive(Clone, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

impl ObjectIdentity {
    fn capture(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct StagingName(String);

impl StagingName {
    fn for_session(session_id: &SessionId) -> Result<Self, StagingError> {
        let Some(hex) = session_id.as_str().strip_prefix("ses_") else {
            return Err(StagingError::InvalidSessionIdentifier);
        };
        let value = format!("{STAGING_NAME_PREFIX}{hex}");

        if !is_valid_staging_name(&value) {
            return Err(StagingError::InvalidSessionIdentifier);
        }

        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_staging_name(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(STAGING_NAME_PREFIX) else {
        return false;
    };

    hex.len() == STAGING_NAME_HEX_LENGTH
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// An approved existing parent directory held as an open capability.
pub struct StagingParent {
    canonical_path: PathBuf,
    directory: Dir,
}

impl StagingParent {
    /// Opens and validates an existing Rust-local staging parent.
    ///
    /// # Errors
    ///
    /// Returns a path-free error when the parent is absent, linked, a Windows
    /// reparse point, not a directory, or cannot be held as a directory
    /// capability.
    pub fn open(path: &Path) -> Result<Self, StagingError> {
        let initial = std_fs::symlink_metadata(path).map_err(|_| StagingError::InvalidParent)?;

        if !initial.is_dir() || standard_metadata_is_link_or_reparse(&initial) {
            return Err(StagingError::InvalidParent);
        }

        let canonical_path = std_fs::canonicalize(path).map_err(|_| StagingError::InvalidParent)?;
        let canonical =
            std_fs::symlink_metadata(&canonical_path).map_err(|_| StagingError::InvalidParent)?;

        if !canonical.is_dir() || standard_metadata_is_link_or_reparse(&canonical) {
            return Err(StagingError::InvalidParent);
        }

        let directory = Dir::open_ambient_dir(&canonical_path, ambient_authority())
            .map_err(|_| StagingError::ParentOpenFailed)?;
        let handle = directory
            .dir_metadata()
            .map_err(|_| StagingError::ParentOpenFailed)?;

        if !handle.is_dir() || handle.is_symlink() {
            return Err(StagingError::InvalidParent);
        }

        Ok(Self {
            canonical_path,
            directory,
        })
    }
}

impl fmt::Debug for StagingParent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagingParent([redacted])")
    }
}

/// A Rust-created staging root bound to one custody-session identifier.
pub struct ControlledStagingRoot {
    session_id: SessionId,
    canonical_path: PathBuf,
    identity: ObjectIdentity,
    directory: Dir,
    staging: StagingRoot,
}

impl ControlledStagingRoot {
    /// Creates one private root and immediately acquires its first lease.
    ///
    /// Creation is accepted only while the supplied session is `created`.
    /// The child is created relative to the approved parent capability.
    ///
    /// # Errors
    ///
    /// Returns a path-free error when state, creation, identity, permissions,
    /// or initial lease acquisition cannot be proven.
    pub fn create(
        parent: &StagingParent,
        session: &CustodySession,
    ) -> Result<(Self, SessionLease), StagingError> {
        if session.state() != SessionState::Created {
            return Err(StagingError::SessionNotCreated);
        }

        let name = StagingName::for_session(session.session_id())?;
        create_child_directory(&parent.directory, name.as_str())?;

        let canonical_path = parent.canonical_path.join(name.as_str());
        let directory = parent
            .directory
            .open_dir(name.as_str())
            .map_err(|_| StagingError::RootOpenFailed)?;

        validate_created_directory(parent, &name, &directory)?;
        apply_and_verify_directory_policy(&canonical_path)?;
        validate_created_directory(parent, &name, &directory)?;

        let metadata = directory
            .dir_metadata()
            .map_err(|_| StagingError::RootOpenFailed)?;
        let identity = ObjectIdentity::capture(&metadata);
        let staging =
            StagingRoot::open(&canonical_path).map_err(|_| StagingError::RootOpenFailed)?;

        let root = Self {
            session_id: session.session_id().clone(),
            canonical_path,
            identity,
            directory,
            staging,
        };
        let lease = root.acquire_lease(session)?;

        Ok((root, lease))
    }

    /// Acquires an exclusive lease for the same session and root.
    ///
    /// # Errors
    ///
    /// Returns a path-free error when the session differs, is disposed, a live
    /// lease already exists, or the lock file policy cannot be proven.
    pub fn acquire_lease(&self, session: &CustodySession) -> Result<SessionLease, StagingError> {
        if session.state() == SessionState::Disposed {
            return Err(StagingError::SessionDisposed);
        }
        if session.session_id() != &self.session_id {
            return Err(StagingError::SessionMismatch);
        }

        let directory = self
            .directory
            .try_clone()
            .map_err(|_| StagingError::LeaseCreationFailed)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        options.mode(0o600);

        let mut file = match directory.open_with(LEASE_FILE_NAME, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StagingError::LeaseUnavailable);
            }
            Err(_) => return Err(StagingError::LeaseCreationFailed),
        };

        if file.write_all(LEASE_MARKER).is_err() || file.sync_all().is_err() {
            abandon_lease_file(&directory, file);
            return Err(StagingError::LeaseCreationFailed);
        }

        let lease_path = self.canonical_path.join(LEASE_FILE_NAME);

        if apply_and_verify_control_file_policy(&lease_path).is_err() {
            abandon_lease_file(&directory, file);
            return Err(StagingError::LeasePolicyFailed);
        }

        let Ok(path_metadata) = directory.symlink_metadata(LEASE_FILE_NAME) else {
            abandon_lease_file(&directory, file);
            return Err(StagingError::LeasePolicyFailed);
        };
        let Ok(handle_metadata) = file.metadata() else {
            abandon_lease_file(&directory, file);
            return Err(StagingError::LeasePolicyFailed);
        };

        if path_metadata.is_symlink()
            || !path_metadata.is_file()
            || path_metadata.nlink() != 1
            || handle_metadata.is_symlink()
            || !handle_metadata.is_file()
            || handle_metadata.nlink() != 1
            || ObjectIdentity::capture(&path_metadata) != ObjectIdentity::capture(&handle_metadata)
        {
            abandon_lease_file(&directory, file);
            return Err(StagingError::LeasePolicyFailed);
        }

        Ok(SessionLease {
            session_id: session.session_id().clone(),
            root_identity: self.identity.clone(),
            lease_identity: ObjectIdentity::capture(&handle_metadata),
            directory,
            file: Some(file),
        })
    }
}

impl fmt::Debug for ControlledStagingRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlledStagingRoot([redacted])")
    }
}

/// One live exclusive lease over a controlled staging root.
pub struct SessionLease {
    session_id: SessionId,
    root_identity: ObjectIdentity,
    lease_identity: ObjectIdentity,
    directory: Dir,
    file: Option<File>,
}

impl SessionLease {
    /// Reports whether this in-memory lease still owns its open lock handle.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.file.is_some()
    }
}

impl fmt::Debug for SessionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionLease([redacted])")
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        let file = self.file.take();
        drop(file);
        let _ = self.directory.remove_file(LEASE_FILE_NAME);
    }
}

/// Creates or acquires a controlled staging root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagingError {
    SessionNotCreated,
    SessionDisposed,
    SessionMismatch,
    InvalidSessionIdentifier,
    InvalidParent,
    ParentOpenFailed,
    StagingAlreadyExists,
    StagingCreationFailed,
    RootOpenFailed,
    RootIdentityChanged,
    RootPolicyFailed,
    LeaseUnavailable,
    LeaseCreationFailed,
    LeasePolicyFailed,
}

impl fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionNotCreated => "custody session is not created",
            Self::SessionDisposed => "custody session is disposed",
            Self::SessionMismatch => "custody session does not own the staging root",
            Self::InvalidSessionIdentifier => "invalid custody-session staging identifier",
            Self::InvalidParent => "invalid controlled staging parent",
            Self::ParentOpenFailed => "controlled staging parent open failed",
            Self::StagingAlreadyExists => "controlled staging root already exists",
            Self::StagingCreationFailed => "controlled staging root creation failed",
            Self::RootOpenFailed => "controlled staging root open failed",
            Self::RootIdentityChanged => "controlled staging root identity changed",
            Self::RootPolicyFailed => "controlled staging root policy verification failed",
            Self::LeaseUnavailable => "controlled staging lease unavailable",
            Self::LeaseCreationFailed => "controlled staging lease creation failed",
            Self::LeasePolicyFailed => "controlled staging lease policy verification failed",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for StagingError {}

/// Failure from a lease-bound controlled source read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlledReadError {
    SessionMismatch,
    LeaseInactive,
    RootChanged,
    LeaseChanged,
    Source(SourceReadError),
}

impl fmt::Display for ControlledReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionMismatch => "custody session or lease mismatch",
            Self::LeaseInactive => "controlled staging lease is inactive",
            Self::RootChanged => "controlled staging root changed",
            Self::LeaseChanged => "controlled staging lease changed",
            Self::Source(_) => "controlled synthetic source read failed",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for ControlledReadError {}

/// Reads one synthetic source only through a matching active lease.
///
/// # Errors
///
/// Returns a path-free error when the session, root or lease do not match,
/// when the root or lease identity changed, or when the bounded source read
/// fails.
pub fn read_controlled_synthetic_source(
    session: &CustodySession,
    root: &ControlledStagingRoot,
    lease: &SessionLease,
    source_name: &SourceName,
    limit: SourceReadLimit,
) -> Result<GuardedSource, ControlledReadError> {
    if session.session_id() != &root.session_id
        || session.session_id() != &lease.session_id
        || root.identity != lease.root_identity
    {
        return Err(ControlledReadError::SessionMismatch);
    }
    if !lease.is_active() {
        return Err(ControlledReadError::LeaseInactive);
    }

    let root_metadata = root
        .directory
        .dir_metadata()
        .map_err(|_| ControlledReadError::RootChanged)?;

    if ObjectIdentity::capture(&root_metadata) != root.identity {
        return Err(ControlledReadError::RootChanged);
    }

    let lease_path_metadata = root
        .directory
        .symlink_metadata(LEASE_FILE_NAME)
        .map_err(|_| ControlledReadError::LeaseChanged)?;
    let lease_handle_metadata = lease
        .file
        .as_ref()
        .ok_or(ControlledReadError::LeaseInactive)?
        .metadata()
        .map_err(|_| ControlledReadError::LeaseChanged)?;

    if lease_path_metadata.is_symlink()
        || !lease_path_metadata.is_file()
        || lease_path_metadata.nlink() != 1
        || ObjectIdentity::capture(&lease_path_metadata) != lease.lease_identity
        || ObjectIdentity::capture(&lease_handle_metadata) != lease.lease_identity
    {
        return Err(ControlledReadError::LeaseChanged);
    }

    read_synthetic_source(session, &root.staging, source_name, limit)
        .map_err(ControlledReadError::Source)
}

fn create_child_directory(parent: &Dir, name: &str) -> Result<(), StagingError> {
    #[cfg(unix)]
    {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);

        match parent.create_dir_with(name, &builder) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(StagingError::StagingAlreadyExists)
            }
            Err(_) => Err(StagingError::StagingCreationFailed),
        }
    }

    #[cfg(not(unix))]
    {
        match parent.create_dir(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(StagingError::StagingAlreadyExists)
            }
            Err(_) => Err(StagingError::StagingCreationFailed),
        }
    }
}

fn validate_created_directory(
    parent: &StagingParent,
    name: &StagingName,
    directory: &Dir,
) -> Result<(), StagingError> {
    let standard = std_fs::symlink_metadata(parent.canonical_path.join(name.as_str()))
        .map_err(|_| StagingError::RootOpenFailed)?;

    if !standard.is_dir() || standard_metadata_is_link_or_reparse(&standard) {
        return Err(StagingError::RootPolicyFailed);
    }

    let path_metadata = parent
        .directory
        .symlink_metadata(name.as_str())
        .map_err(|_| StagingError::RootOpenFailed)?;
    let handle_metadata = directory
        .dir_metadata()
        .map_err(|_| StagingError::RootOpenFailed)?;

    if !path_metadata.is_dir()
        || path_metadata.is_symlink()
        || !handle_metadata.is_dir()
        || handle_metadata.is_symlink()
        || ObjectIdentity::capture(&path_metadata) != ObjectIdentity::capture(&handle_metadata)
    {
        return Err(StagingError::RootIdentityChanged);
    }

    Ok(())
}

fn abandon_lease_file(directory: &Dir, file: File) {
    drop(file);
    let _ = directory.remove_file(LEASE_FILE_NAME);
}

#[cfg(unix)]
fn apply_and_verify_directory_policy(path: &Path) -> Result<(), StagingError> {
    verify_unix_mode(path, 0o700).map_err(|()| StagingError::RootPolicyFailed)
}

#[cfg(windows)]
fn apply_and_verify_directory_policy(path: &Path) -> Result<(), StagingError> {
    apply_and_verify_windows_policy(path, true).map_err(|()| StagingError::RootPolicyFailed)
}

#[cfg(unix)]
fn apply_and_verify_control_file_policy(path: &Path) -> Result<(), StagingError> {
    verify_unix_mode(path, 0o600).map_err(|()| StagingError::LeasePolicyFailed)
}

#[cfg(windows)]
fn apply_and_verify_control_file_policy(path: &Path) -> Result<(), StagingError> {
    apply_and_verify_windows_policy(path, false).map_err(|()| StagingError::LeasePolicyFailed)
}

#[cfg(not(any(unix, windows)))]
fn apply_and_verify_directory_policy(_path: &Path) -> Result<(), StagingError> {
    Err(StagingError::RootPolicyFailed)
}

#[cfg(not(any(unix, windows)))]
fn apply_and_verify_control_file_policy(_path: &Path) -> Result<(), StagingError> {
    Err(StagingError::LeasePolicyFailed)
}

#[cfg(unix)]
fn verify_unix_mode(path: &Path, expected: u32) -> Result<(), ()> {
    let metadata = std_fs::symlink_metadata(path).map_err(|_| ())?;

    if metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o777 != expected {
        return Err(());
    }

    Ok(())
}

#[cfg(windows)]
fn apply_and_verify_windows_policy(path: &Path, directory: bool) -> Result<(), ()> {
    use windows_permissions::constants::{
        AccessRights, AceFlags, AceType, SeObjectType::SE_FILE_OBJECT, SecurityInformation,
    };
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, ConvertSidToStringSid,
        GetSecurityInfo, SetSecurityInfo,
    };
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let mut options = std_fs::OpenOptions::new();
    options.access_mode(READ_CONTROL | WRITE_DAC);

    if directory {
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }

    let mut handle = options.open(path).map_err(|_| ())?;

    // Windows assigns a new object's owner from TokenOwner, which is not
    // necessarily TokenUser for an elevated administrator token. Capture the
    // owner from the opened object and bind the sole ACE to that exact SID.
    let initial =
        GetSecurityInfo(&handle, SE_FILE_OBJECT, SecurityInformation::Owner).map_err(|_| ())?;
    let owner = initial.owner().ok_or(())?;
    let owner_text = ConvertSidToStringSid(owner)
        .map_err(|_| ())?
        .to_string_lossy()
        .into_owned();
    let expected_ace = if directory {
        format!("(A;OICI;FA;;;{owner_text})")
    } else {
        format!("(A;;FA;;;{owner_text})")
    };
    let requested: LocalBox<SecurityDescriptor> =
        format!("D:P{expected_ace}").parse().map_err(|_| ())?;
    let requested_dacl = requested.dacl().ok_or(())?;

    SetSecurityInfo(
        &mut handle,
        SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(requested_dacl),
        None,
    )
    .map_err(|_| ())?;

    let observed = GetSecurityInfo(
        &handle,
        SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| ())?;
    let observed_owner = observed.owner().ok_or(())?;
    let observed_dacl = observed.dacl().ok_or(())?;
    let observed_ace = observed_dacl.get_ace(0).ok_or(())?;
    let observed_dacl_sddl =
        ConvertSecurityDescriptorToStringSecurityDescriptor(&observed, SecurityInformation::Dacl)
            .map_err(|_| ())?
            .to_string_lossy()
            .into_owned();
    let expected_flags = if directory {
        AceFlags::ObjectInherit | AceFlags::ContainerInherit
    } else {
        AceFlags::empty()
    };

    if observed_owner != owner
        || !observed_dacl_sddl.starts_with("D:P")
        || observed_dacl.len() != 1
        || observed_ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
        || observed_ace.flags() != expected_flags
        || observed_ace.mask() != AccessRights::FileAllAccess
        || observed_ace.sid() != Some(owner)
    {
        return Err(());
    }

    Ok(())
}

fn standard_metadata_is_link_or_reparse(metadata: &std_fs::Metadata) -> bool {
    let is_symlink = metadata.file_type().is_symlink();

    #[cfg(windows)]
    {
        is_symlink || metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
        is_symlink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionAction;
    use std::error::Error;
    use std::io;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
    const SESSION: &str = "ses_0123456789abcdef0123456789abcdef";
    const OTHER_SESSION: &str = "ses_fedcba9876543210fedcba9876543210";
    const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";

    struct TempParent {
        path: PathBuf,
    }

    impl TempParent {
        fn new() -> io::Result<Self> {
            let parent = std::env::temp_dir();

            for _ in 0..100 {
                let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    "systeme-local-controlled-staging-{}-{nonce}",
                    std::process::id()
                ));

                match std_fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }

            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unable to allocate controlled staging test parent",
            ))
        }
    }

    impl Drop for TempParent {
        fn drop(&mut self) {
            let _ = std_fs::remove_dir_all(&self.path);
        }
    }

    fn created_session(value: &str) -> Result<CustodySession, Box<dyn Error>> {
        Ok(CustodySession::new(SessionId::from_str(value)?))
    }

    #[test]
    fn staging_name_contract_is_exact() -> Result<(), Box<dyn Error>> {
        let session = created_session(SESSION)?;
        let name = StagingName::for_session(session.session_id())?;

        assert_eq!(name.as_str(), "stg_0123456789abcdef0123456789abcdef");

        for invalid in [
            "",
            "stg_0123456789abcdef0123456789abcde",
            "stg_0123456789abcdef0123456789abcdef0",
            "stg_0123456789ABCDEF0123456789ABCDEF",
            "stg_../../../../secret",
            "ses_0123456789abcdef0123456789abcdef",
        ] {
            assert!(!is_valid_staging_name(invalid));
        }

        Ok(())
    }

    #[test]
    fn creation_requires_created_state() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let mut session = created_session(SESSION)?;
        session.apply(SessionAction::BeginCollection)?;

        let result = ControlledStagingRoot::create(&parent, &session);

        assert!(matches!(result, Err(StagingError::SessionNotCreated)));
        Ok(())
    }

    #[test]
    fn creation_is_exclusive_and_policies_are_exact() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let session = created_session(SESSION)?;
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;

        assert!(lease.is_active());

        let duplicate = ControlledStagingRoot::create(&parent, &session);
        assert!(matches!(duplicate, Err(StagingError::StagingAlreadyExists)));

        #[cfg(unix)]
        {
            assert_eq!(
                std_fs::metadata(&root.canonical_path)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std_fs::metadata(root.canonical_path.join(LEASE_FILE_NAME))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        #[cfg(windows)]
        {
            assert!(apply_and_verify_windows_policy(&root.canonical_path, true).is_ok());
            assert!(
                apply_and_verify_windows_policy(&root.canonical_path.join(LEASE_FILE_NAME), false)
                    .is_ok()
            );
        }

        Ok(())
    }

    #[test]
    fn lease_is_exclusive_and_reacquirable_after_drop() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let session = created_session(SESSION)?;
        let (root, first) = ControlledStagingRoot::create(&parent, &session)?;

        assert!(matches!(
            root.acquire_lease(&session),
            Err(StagingError::LeaseUnavailable)
        ));

        drop(first);

        let second = root.acquire_lease(&session)?;
        assert!(second.is_active());
        Ok(())
    }

    #[test]
    fn different_session_cannot_acquire_or_read() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let session = created_session(SESSION)?;
        let other = created_session(OTHER_SESSION)?;
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;

        assert!(matches!(
            root.acquire_lease(&other),
            Err(StagingError::SessionMismatch)
        ));

        let result = read_controlled_synthetic_source(
            &other,
            &root,
            &lease,
            &SourceName::from_str(SOURCE)?,
            SourceReadLimit::new(32)?,
        );
        assert!(matches!(result, Err(ControlledReadError::SessionMismatch)));
        Ok(())
    }

    #[test]
    fn controlled_read_requires_collecting_and_matching_lease() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let mut session = created_session(SESSION)?;
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;
        std_fs::write(root.canonical_path.join(SOURCE), b"synthetic-controlled")?;

        let before_collection = read_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &SourceName::from_str(SOURCE)?,
            SourceReadLimit::new(64)?,
        );
        assert!(matches!(
            before_collection,
            Err(ControlledReadError::Source(
                SourceReadError::SessionNotCollecting
            ))
        ));

        session.apply(SessionAction::BeginCollection)?;

        let guarded = read_controlled_synthetic_source(
            &session,
            &root,
            &lease,
            &SourceName::from_str(SOURCE)?,
            SourceReadLimit::new(64)?,
        )?;
        assert_eq!(guarded.byte_len(), 20);
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let parent = StagingParent::open(&temp.path)?;
        let session = created_session(SESSION)?;
        let (root, lease) = ControlledStagingRoot::create(&parent, &session)?;

        for rendered in [
            format!("{parent:?}"),
            format!("{root:?}"),
            format!("{lease:?}"),
        ] {
            assert!(rendered.contains("[redacted]"));
            assert!(!rendered.contains(SESSION));
            assert!(!rendered.contains(&temp.path.to_string_lossy().to_string()));
        }

        Ok(())
    }

    #[test]
    fn parent_symlink_is_rejected_when_supported() -> Result<(), Box<dyn Error>> {
        let temp = TempParent::new()?;
        let real = temp.path.join("real");
        let link = temp.path.join("linked");
        std_fs::create_dir(&real)?;

        if !create_dir_symlink(&real, &link)? {
            return Ok(());
        }

        assert!(matches!(
            StagingParent::open(&link),
            Err(StagingError::InvalidParent)
        ));
        Ok(())
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<bool> {
        std::os::unix::fs::symlink(target, link)?;
        Ok(true)
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<bool> {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => Ok(true),
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}
