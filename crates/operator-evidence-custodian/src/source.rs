use crate::session::{CustodySession, SessionState};
use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
#[cfg(windows)]
use cap_std::fs::File;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use cap_std::time::SystemTime;
use std::fmt;
use std::fs as std_fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub const MAX_SYNTHETIC_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
pub const SOURCE_READ_CHUNK_BYTES: usize = 16 * 1024;

const SOURCE_NAME_PREFIX: &str = "src_";
const SOURCE_NAME_SUFFIX: &str = ".raw";
const SOURCE_NAME_HEX_LENGTH: usize = 32;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceName(String);

impl SourceName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SourceName {
    type Err = SourceNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(without_prefix) = value.strip_prefix(SOURCE_NAME_PREFIX) else {
            return Err(SourceNameError);
        };
        let Some(hex) = without_prefix.strip_suffix(SOURCE_NAME_SUFFIX) else {
            return Err(SourceNameError);
        };

        if hex.len() != SOURCE_NAME_HEX_LENGTH
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SourceNameError);
        }

        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for SourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceName([opaque])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceNameError;

impl fmt::Display for SourceNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid synthetic source name")
    }
}

impl std::error::Error for SourceNameError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReadLimit(u64);

impl SourceReadLimit {
    /// Constructs a bounded synthetic source limit.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is zero or exceeds
    /// [`MAX_SYNTHETIC_SOURCE_BYTES`].
    pub fn new(value: u64) -> Result<Self, SourceReadLimitError> {
        if value == 0 || value > MAX_SYNTHETIC_SOURCE_BYTES {
            return Err(SourceReadLimitError);
        }

        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReadLimitError;

impl fmt::Display for SourceReadLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid synthetic source read limit")
    }
}

impl std::error::Error for SourceReadLimitError {}

pub struct StagingRoot {
    canonical_path: PathBuf,
    directory: Dir,
}

impl StagingRoot {
    /// Opens an existing synthetic staging directory as a capability root.
    ///
    /// # Errors
    ///
    /// Returns a path-free error when the root is absent, not a directory,
    /// linked, a Windows reparse point or cannot be opened as a directory
    /// capability.
    pub fn open(path: &Path) -> Result<Self, SourceReadError> {
        let initial_metadata =
            std_fs::symlink_metadata(path).map_err(|_| SourceReadError::InvalidStagingRoot)?;

        if !initial_metadata.is_dir() || std_metadata_is_link_or_reparse(&initial_metadata) {
            return Err(SourceReadError::InvalidStagingRoot);
        }

        let canonical_path =
            std_fs::canonicalize(path).map_err(|_| SourceReadError::InvalidStagingRoot)?;
        let canonical_metadata = std_fs::symlink_metadata(&canonical_path)
            .map_err(|_| SourceReadError::InvalidStagingRoot)?;

        if !canonical_metadata.is_dir() || std_metadata_is_link_or_reparse(&canonical_metadata) {
            return Err(SourceReadError::InvalidStagingRoot);
        }

        let directory = Dir::open_ambient_dir(&canonical_path, ambient_authority())
            .map_err(|_| SourceReadError::InvalidStagingRoot)?;
        let handle_metadata = directory
            .dir_metadata()
            .map_err(|_| SourceReadError::InvalidStagingRoot)?;

        if !handle_metadata.is_dir() || handle_metadata.is_symlink() {
            return Err(SourceReadError::InvalidStagingRoot);
        }

        Ok(Self {
            canonical_path,
            directory,
        })
    }
}

impl fmt::Debug for StagingRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagingRoot([redacted])")
    }
}

pub struct GuardedSource {
    bytes: Vec<u8>,
}

impl GuardedSource {
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn commitment_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sanitizer_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

impl fmt::Debug for GuardedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedSource")
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl Drop for GuardedSource {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceReadError {
    SessionNotCollecting,
    InvalidStagingRoot,
    SourceUnavailable,
    SourceLinkRejected,
    SourceNotRegularFile,
    SourceHardLinkRejected,
    SourceTooLarge,
    SourceOpenFailed,
    SourceReadFailed,
    SourceChanged,
    CapacityOverflow,
}

impl fmt::Display for SourceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionNotCollecting => "custody session is not collecting",
            Self::InvalidStagingRoot => "invalid synthetic staging root",
            Self::SourceUnavailable => "synthetic source unavailable",
            Self::SourceLinkRejected => "linked synthetic source rejected",
            Self::SourceNotRegularFile => "synthetic source is not a regular file",
            Self::SourceHardLinkRejected => "multiply-linked synthetic source rejected",
            Self::SourceTooLarge => "synthetic source exceeds the read limit",
            Self::SourceOpenFailed => "synthetic source open failed",
            Self::SourceReadFailed => "synthetic source read failed",
            Self::SourceChanged => "synthetic source changed during custody",
            Self::CapacityOverflow => "synthetic source capacity overflow",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for SourceReadError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceFingerprint {
    device: u64,
    inode: u64,
    hard_links: u64,
    byte_len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
}

impl SourceFingerprint {
    fn capture(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            hard_links: metadata.nlink(),
            byte_len: metadata.len(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        }
    }
}

/// Reads one synthetic staged source into Rust-owned guarded memory.
///
/// # Errors
///
/// Returns a path-free typed error unless the session is collecting, the
/// source is a single-link regular direct child of `staging`, every observed
/// fingerprint remains stable and the read stays within `limit`.
pub fn read_synthetic_source(
    session: &CustodySession,
    staging: &StagingRoot,
    source_name: &SourceName,
    limit: SourceReadLimit,
) -> Result<GuardedSource, SourceReadError> {
    if session.state() != SessionState::Collecting {
        return Err(SourceReadError::SessionNotCollecting);
    }

    let candidate_path = staging.canonical_path.join(source_name.as_str());
    let standard_metadata =
        std_fs::symlink_metadata(candidate_path).map_err(|_| SourceReadError::SourceUnavailable)?;

    if std_metadata_is_link_or_reparse(&standard_metadata) {
        return Err(SourceReadError::SourceLinkRejected);
    }

    let before_metadata = staging
        .directory
        .symlink_metadata(source_name.as_str())
        .map_err(|_| SourceReadError::SourceUnavailable)?;

    validate_source_metadata(&before_metadata, limit)?;

    let before = SourceFingerprint::capture(&before_metadata);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);

    let mut file = staging
        .directory
        .open_with(source_name.as_str(), &options)
        .map_err(|_| SourceReadError::SourceOpenFailed)?;

    #[cfg(windows)]
    if opened_file_is_reparse(&file)? {
        return Err(SourceReadError::SourceLinkRejected);
    }

    let handle_metadata = file
        .metadata()
        .map_err(|_| SourceReadError::SourceOpenFailed)?;
    validate_source_metadata(&handle_metadata, limit)?;

    let handle = SourceFingerprint::capture(&handle_metadata);

    if handle != before {
        return Err(SourceReadError::SourceChanged);
    }

    let capacity =
        usize::try_from(handle.byte_len).map_err(|_| SourceReadError::CapacityOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; SOURCE_READ_CHUNK_BYTES];

    loop {
        let Ok(read) = file.read(&mut chunk) else {
            bytes.fill(0);
            return Err(SourceReadError::SourceReadFailed);
        };

        if read == 0 {
            break;
        }

        let Some(next_len) = bytes.len().checked_add(read) else {
            bytes.fill(0);
            return Err(SourceReadError::CapacityOverflow);
        };
        let Ok(next_len_u64) = u64::try_from(next_len) else {
            bytes.fill(0);
            return Err(SourceReadError::CapacityOverflow);
        };

        if next_len_u64 > limit.get() {
            bytes.fill(0);
            return Err(SourceReadError::SourceTooLarge);
        }

        bytes.extend_from_slice(&chunk[..read]);
    }

    let Ok(after_metadata) = file.metadata() else {
        bytes.fill(0);
        return Err(SourceReadError::SourceChanged);
    };
    let after = SourceFingerprint::capture(&after_metadata);
    let Ok(observed_len) = u64::try_from(bytes.len()) else {
        bytes.fill(0);
        return Err(SourceReadError::CapacityOverflow);
    };

    if after != handle || observed_len != after.byte_len {
        bytes.fill(0);
        return Err(SourceReadError::SourceChanged);
    }

    Ok(GuardedSource { bytes })
}

fn validate_source_metadata(
    metadata: &Metadata,
    limit: SourceReadLimit,
) -> Result<(), SourceReadError> {
    if metadata.is_symlink() {
        return Err(SourceReadError::SourceLinkRejected);
    }
    if !metadata.is_file() {
        return Err(SourceReadError::SourceNotRegularFile);
    }
    if metadata.nlink() != 1 {
        return Err(SourceReadError::SourceHardLinkRejected);
    }
    if metadata.len() > limit.get() {
        return Err(SourceReadError::SourceTooLarge);
    }

    Ok(())
}

fn std_metadata_is_link_or_reparse(metadata: &std_fs::Metadata) -> bool {
    let is_symlink = metadata.file_type().is_symlink();

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        is_symlink || metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
        is_symlink
    }
}

#[cfg(windows)]
fn opened_file_is_reparse(file: &File) -> Result<bool, SourceReadError> {
    use std::os::windows::fs::MetadataExt as _;

    let standard_file = file
        .try_clone()
        .map_err(|_| SourceReadError::SourceOpenFailed)?
        .into_std();
    let metadata = standard_file
        .metadata()
        .map_err(|_| SourceReadError::SourceOpenFailed)?;

    Ok(metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionAction, SessionId};
    use std::error::Error;
    use std::io;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
    const SOURCE: &str = "src_0123456789abcdef0123456789abcdef.raw";

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> io::Result<Self> {
            let parent = std::env::temp_dir();

            for _ in 0..100 {
                let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    "systeme-local-source-{}-{nonce}",
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
                "unable to allocate synthetic test directory",
            ))
        }

        fn staging_path(&self) -> PathBuf {
            self.path.join("staging")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std_fs::remove_dir_all(&self.path);
        }
    }

    fn source_name() -> Result<SourceName, SourceNameError> {
        SourceName::from_str(SOURCE)
    }

    fn collecting_session() -> Result<CustodySession, Box<dyn Error>> {
        let mut session =
            CustodySession::new(SessionId::from_str("ses_0123456789abcdef0123456789abcdef")?);
        session.apply(SessionAction::BeginCollection)?;
        Ok(session)
    }

    fn staging_fixture() -> Result<(TempRoot, StagingRoot), Box<dyn Error>> {
        let temp = TempRoot::new()?;
        let staging_path = temp.staging_path();
        std_fs::create_dir(&staging_path)?;
        let staging = StagingRoot::open(&staging_path)?;
        Ok((temp, staging))
    }

    #[test]
    fn source_name_contract_is_exact() -> Result<(), Box<dyn Error>> {
        assert_eq!(source_name()?.as_str(), SOURCE);

        for invalid in [
            "",
            "src_0123456789abcdef0123456789abcde.raw",
            "src_0123456789abcdef0123456789abcdef0.raw",
            "src_0123456789ABCDEF0123456789ABCDEF.raw",
            "src_0123456789abcdef/123456789abcdef.raw",
            "src_../../../../secret.raw",
            "src_0123456789abcdef0123456789abcdef.txt",
            "ses_0123456789abcdef0123456789abcdef.raw",
        ] {
            assert!(SourceName::from_str(invalid).is_err());
        }

        Ok(())
    }

    #[test]
    fn read_limit_contract_is_bounded() -> Result<(), Box<dyn Error>> {
        assert!(SourceReadLimit::new(0).is_err());
        assert_eq!(SourceReadLimit::new(1)?.get(), 1);
        assert_eq!(
            SourceReadLimit::new(MAX_SYNTHETIC_SOURCE_BYTES)?.get(),
            MAX_SYNTHETIC_SOURCE_BYTES
        );
        assert!(SourceReadLimit::new(MAX_SYNTHETIC_SOURCE_BYTES + 1).is_err());
        Ok(())
    }

    #[test]
    fn read_requires_collecting_state() -> Result<(), Box<dyn Error>> {
        let (temp, staging) = staging_fixture()?;
        std_fs::write(temp.staging_path().join(SOURCE), b"synthetic")?;
        let session =
            CustodySession::new(SessionId::from_str("ses_0123456789abcdef0123456789abcdef")?);

        let result = read_synthetic_source(
            &session,
            &staging,
            &source_name()?,
            SourceReadLimit::new(32)?,
        );

        assert!(matches!(result, Err(SourceReadError::SessionNotCollecting)));
        Ok(())
    }

    #[test]
    fn ordinary_and_exact_limit_reads_succeed() -> Result<(), Box<dyn Error>> {
        let (temp, staging) = staging_fixture()?;
        let content = vec![0x5a; SOURCE_READ_CHUNK_BYTES * 2];
        std_fs::write(temp.staging_path().join(SOURCE), &content)?;
        let session = collecting_session()?;
        let guarded = read_synthetic_source(
            &session,
            &staging,
            &source_name()?,
            SourceReadLimit::new(u64::try_from(content.len())?)?,
        )?;

        assert_eq!(guarded.bytes, content);
        assert_eq!(guarded.byte_len(), SOURCE_READ_CHUNK_BYTES * 2);
        assert!(!guarded.is_empty());
        Ok(())
    }

    #[test]
    fn oversized_source_fails_closed() -> Result<(), Box<dyn Error>> {
        let (temp, staging) = staging_fixture()?;
        std_fs::write(temp.staging_path().join(SOURCE), vec![0x41; 33])?;
        let session = collecting_session()?;
        let result = read_synthetic_source(
            &session,
            &staging,
            &source_name()?,
            SourceReadLimit::new(32)?,
        );

        assert!(matches!(result, Err(SourceReadError::SourceTooLarge)));
        Ok(())
    }

    #[test]
    fn directory_and_hard_link_sources_are_rejected() -> Result<(), Box<dyn Error>> {
        let temp = TempRoot::new()?;
        let staging_path = temp.staging_path();
        std_fs::create_dir(&staging_path)?;
        std_fs::create_dir(staging_path.join(SOURCE))?;
        let staging = StagingRoot::open(&staging_path)?;
        let session = collecting_session()?;

        let directory_result = read_synthetic_source(
            &session,
            &staging,
            &source_name()?,
            SourceReadLimit::new(32)?,
        );
        assert!(matches!(
            directory_result,
            Err(SourceReadError::SourceNotRegularFile)
        ));

        drop(staging);
        std_fs::remove_dir(staging_path.join(SOURCE))?;
        let outside = temp.path.join("outside.raw");
        std_fs::write(&outside, b"hard-link")?;
        std_fs::hard_link(&outside, staging_path.join(SOURCE))?;
        let staging = StagingRoot::open(&staging_path)?;

        let hard_link_result = read_synthetic_source(
            &session,
            &staging,
            &source_name()?,
            SourceReadLimit::new(32)?,
        );
        assert!(matches!(
            hard_link_result,
            Err(SourceReadError::SourceHardLinkRejected)
        ));
        Ok(())
    }

    #[test]
    fn source_symlink_is_rejected_when_supported() -> Result<(), Box<dyn Error>> {
        let (temp, staging) = staging_fixture()?;
        let outside = temp.path.join("outside.raw");
        std_fs::write(&outside, b"outside")?;
        let link = temp.staging_path().join(SOURCE);

        if !create_file_symlink(&outside, &link)? {
            return Ok(());
        }

        let result = read_synthetic_source(
            &collecting_session()?,
            &staging,
            &source_name()?,
            SourceReadLimit::new(32)?,
        );

        assert!(matches!(
            result,
            Err(SourceReadError::SourceLinkRejected | SourceReadError::SourceOpenFailed)
        ));
        Ok(())
    }

    #[test]
    fn staging_root_symlink_is_rejected_when_supported() -> Result<(), Box<dyn Error>> {
        let temp = TempRoot::new()?;
        let real = temp.path.join("real");
        let link = temp.path.join("linked");
        std_fs::create_dir(&real)?;

        if !create_dir_symlink(&real, &link)? {
            return Ok(());
        }

        assert!(matches!(
            StagingRoot::open(&link),
            Err(SourceReadError::InvalidStagingRoot)
        ));
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> Result<(), Box<dyn Error>> {
        let (temp, staging) = staging_fixture()?;
        std_fs::write(
            temp.staging_path().join(SOURCE),
            b"highly-private-synthetic-bytes",
        )?;
        let guarded = read_synthetic_source(
            &collecting_session()?,
            &staging,
            &source_name()?,
            SourceReadLimit::new(64)?,
        )?;

        let source_debug = format!("{guarded:?}");
        let root_debug = format!("{staging:?}");
        let name_debug = format!("{:?}", source_name()?);

        assert!(!source_debug.contains("highly-private"));
        assert!(source_debug.contains("[redacted]"));
        assert!(!root_debug.contains(&temp.path.to_string_lossy().to_string()));
        assert!(root_debug.contains("[redacted]"));
        assert_eq!(name_debug, "SourceName([opaque])");
        Ok(())
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<bool> {
        std::os::unix::fs::symlink(target, link)?;
        Ok(true)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<bool> {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => Ok(true),
            Err(error) if windows_symlink_creation_unavailable(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[cfg(windows)]
    fn windows_symlink_creation_unavailable(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
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
            Err(error) if windows_symlink_creation_unavailable(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
