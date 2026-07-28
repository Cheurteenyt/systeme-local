Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C9Branch = "codex/chatgpt-file-image-handoff-c9"
$script:C9AcceptedC8Commit = "bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"
$script:C9Port = 8765
$script:C9HealthPort = 8766
$script:C9ToolName = "systeme_local_attachment_handoff"

function Get-C9RepositoryRoot {
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-C9StateDirectory {
    $root = Get-C9RepositoryRoot
    $privateRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local")
    )
    $state = [System.IO.Path]::GetFullPath((Join-Path $privateRoot "c9"))
    $prefix = $privateRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $state.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C9 state directory escaped the repository-private state root."
    }
    return $state
}

function Assert-C9NotReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C9 private state must not traverse a reparse point."
    }
}

function Initialize-C9StateDirectory {
    $root = Get-C9RepositoryRoot
    $privateRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local")
    )
    Assert-C9NotReparsePoint -Path $privateRoot
    if (-not (Test-Path -LiteralPath $privateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $privateRoot | Out-Null
    }
    Assert-C9NotReparsePoint -Path $privateRoot

    $state = Get-C9StateDirectory
    Assert-C9NotReparsePoint -Path $state
    if (-not (Test-Path -LiteralPath $state -PathType Container)) {
        New-Item -ItemType Directory -Path $state | Out-Null
    }
    Assert-C9NotReparsePoint -Path $state
    return $state
}

function Assert-C9StateFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    $state = [System.IO.Path]::GetFullPath((Get-C9StateDirectory))
    $prefix = $state +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C9 runtime paths must remain inside the ignored C9 state directory."
    }
    Assert-C9NotReparsePoint -Path (
        [System.IO.Path]::GetDirectoryName($state)
    )
    Assert-C9NotReparsePoint -Path $state
    $relative = $resolved.Substring($prefix.Length)
    $current = $state
    $separators = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    foreach ($component in $relative.Split(
        $separators,
        [System.StringSplitOptions]::RemoveEmptyEntries
    )) {
        $current = Join-Path $current $component
        Assert-C9NotReparsePoint -Path $current
    }
    return $resolved
}

function Get-C9FileLinkCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (
        [Environment]::OSVersion.Platform -ne
        [PlatformID]::Win32NT
    ) {
        throw "C9 hardlink verification requires Windows."
    }
    if ($null -eq ("SystemeLocal.C9.NativeFile" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SystemeLocal.C9
{
    public static class NativeFile
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information
        );

        public static uint GetLinkCount(string path)
        {
            const uint FileReadAttributes = 0x80;
            const uint ShareRead = 0x1;
            const uint ShareWrite = 0x2;
            const uint ShareDelete = 0x4;
            const uint OpenExisting = 3;
            const uint BackupSemantics = 0x02000000;

            using (
                SafeFileHandle handle = CreateFileW(
                    path,
                    FileReadAttributes,
                    ShareRead | ShareWrite | ShareDelete,
                    IntPtr.Zero,
                    OpenExisting,
                    BackupSemantics,
                    IntPtr.Zero
                )
            )
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to open the C9 execution leaf."
                    );
                }
                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to inspect the C9 execution leaf."
                    );
                }
                return information.NumberOfLinks;
            }
        }
    }
}
'@
    }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    return [SystemeLocal.C9.NativeFile]::GetLinkCount($resolved)
}

function Get-C9GitExecutable {
    $ambientGitVariables = @(
        Get-ChildItem Env: |
            Where-Object { $_.Name -match "^(?i:GIT_)" } |
            Select-Object -ExpandProperty Name
    )
    if ($ambientGitVariables.Count -ne 0) {
        throw "C9 protected runtime refuses ambient GIT_* variables."
    }
    $configured = [Environment]::GetEnvironmentVariable(
        "SLG_C9_GIT_EXECUTABLE",
        "Process"
    )
    if ([string]::IsNullOrWhiteSpace($configured)) {
        $applications = @(
            Get-Command git.exe -CommandType Application -ErrorAction Stop
        )
        if ($applications.Count -lt 1) {
            throw "C9 could not resolve git.exe as an application."
        }
        $configured = [string]$applications[0].Source
    }
    if (
        -not [System.IO.Path]::IsPathRooted($configured) -or
        [System.IO.Path]::GetFileName($configured) -cne "git.exe"
    ) {
        throw "C9 Git executable must be an absolute git.exe path."
    }
    $resolved = [System.IO.Path]::GetFullPath($configured)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "C9 Git executable is not a regular file."
    }
    $sourceCursor = $resolved
    while (-not [string]::IsNullOrWhiteSpace($sourceCursor)) {
        Assert-C9NotReparsePoint -Path $sourceCursor
        $sourceParent = [System.IO.Path]::GetDirectoryName($sourceCursor)
        if (
            [string]::IsNullOrWhiteSpace($sourceParent) -or
            $sourceParent.Equals(
                $sourceCursor,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            break
        }
        $sourceCursor = $sourceParent
    }
    if ((Get-C9FileLinkCount -Path $resolved) -ne 1) {
        $sourceDirectory = [System.IO.Path]::GetDirectoryName($resolved)
        $installationRoot = [System.IO.Path]::GetDirectoryName($sourceDirectory)
        $canonicalCandidate = if (
            [System.IO.Path]::GetFileName($sourceDirectory).Equals(
                "cmd",
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            -not [string]::IsNullOrWhiteSpace($installationRoot)
        ) {
            Join-Path $installationRoot "bin\git.exe"
        } else {
            $null
        }
        if (
            [string]::IsNullOrWhiteSpace($canonicalCandidate) -or
            -not (Test-Path -LiteralPath $canonicalCandidate -PathType Leaf) -or
            (Get-C9FileLinkCount -Path $canonicalCandidate) -ne 1
        ) {
            throw "C9 Git executable must be one non-hardlinked regular file."
        }
        $candidateCursor = [System.IO.Path]::GetFullPath($canonicalCandidate)
        while (-not [string]::IsNullOrWhiteSpace($candidateCursor)) {
            Assert-C9NotReparsePoint -Path $candidateCursor
            $candidateParent = [System.IO.Path]::GetDirectoryName($candidateCursor)
            if (
                [string]::IsNullOrWhiteSpace($candidateParent) -or
                $candidateParent.Equals(
                    $candidateCursor,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                break
            }
            $candidateCursor = $candidateParent
        }
        $sourceHash = (
            Get-FileHash -LiteralPath $resolved -Algorithm SHA256
        ).Hash
        $candidateHash = (
            Get-FileHash -LiteralPath $canonicalCandidate -Algorithm SHA256
        ).Hash
        if ($sourceHash -cne $candidateHash) {
            throw "C9 refused a non-identical canonical Git sibling."
        }
        $resolved = [System.IO.Path]::GetFullPath($canonicalCandidate)
    }
    $application = Get-Command `
        -Name $resolved `
        -CommandType Application `
        -ErrorAction Stop
    if (
        $null -eq $application -or
        -not ([System.IO.Path]::GetFullPath(
            [string]$application.Source
        )).Equals(
            $resolved,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "C9 Git path does not resolve as the exact application."
    }
    $cursor = $resolved
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        Assert-C9NotReparsePoint -Path $cursor
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if (
            [string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals(
                $cursor,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            break
        }
        $cursor = $parent
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (
        $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-C9FileLinkCount -Path $resolved) -ne 1
    ) {
        throw "C9 Git executable must be one non-reparse, non-hardlinked regular file."
    }
    return $resolved
}

function Get-C9GitTrustRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GitExecutable
    )

    $git = [System.IO.Path]::GetFullPath($GitExecutable)
    $directory = [System.IO.Path]::GetDirectoryName($git)
    return [System.IO.Path]::GetFullPath($directory)
}

function Get-C9GitGlobalConfig {
    $state = Initialize-C9StateDirectory
    $path = Assert-C9StateFile -Path (
        Join-Path $state "git-global-config.empty"
    )
    if (-not (Test-Path -LiteralPath $path)) {
        $stream = $null
        try {
            $stream = [System.IO.File]::Open(
                $path,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::Read
            )
            $stream.Flush($true)
        } finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
    }
    $item = Get-Item -LiteralPath $path -Force
    if (
        $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -ne 0 -or
        (Get-C9FileLinkCount -Path $path) -ne 1
    ) {
        throw "C9 Git global configuration must be one empty private regular file."
    }
    [void](Assert-C9TrustedPathChain -Path $path)
    return $path
}

function Invoke-C9Git {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments
    )

    foreach ($argument in $Arguments) {
        if ($null -eq $argument -or $argument.IndexOf([char]0) -ge 0) {
            throw "C9 Git arguments must not contain null or NUL values."
        }
    }
    $git = Get-C9GitExecutable
    $config = Get-C9GitGlobalConfig
    $gitDirectory = [System.IO.Path]::GetDirectoryName($git)
    $system32 = [System.IO.Path]::GetFullPath(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    )
    foreach ($path in @($gitDirectory, $system32)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "C9 cannot construct the protected Git execution environment."
        }
        Assert-C9NotReparsePoint -Path $path
    }

    $controlledNames = @(
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "XDG_CONFIG_HOME",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR"
    )
    $snapshot = @{}
    foreach ($name in $controlledNames) {
        $snapshot[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    $exitCode = $null
    try {
        [Environment]::SetEnvironmentVariable(
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "GIT_CONFIG_GLOBAL",
            $config,
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "GIT_OPTIONAL_LOCKS",
            "0",
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "GIT_TERMINAL_PROMPT",
            "0",
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "HOME",
            (Get-C9StateDirectory),
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "XDG_CONFIG_HOME",
            (Get-C9StateDirectory),
            "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "PATH",
            (
                $gitDirectory +
                [System.IO.Path]::PathSeparator +
                $system32
            ),
            "Process"
        )
        $windowsRoot = [System.IO.Path]::GetDirectoryName($system32)
        foreach ($name in @("SYSTEMROOT", "WINDIR")) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $windowsRoot,
                "Process"
            )
        }
        [Environment]::SetEnvironmentVariable(
            "PATHEXT",
            ".COM;.EXE;.BAT;.CMD",
            "Process"
        )
        foreach ($name in @("TEMP", "TMP")) {
            [Environment]::SetEnvironmentVariable(
                $name,
                (Get-C9StateDirectory),
                "Process"
            )
        }
        $result = Invoke-C9MinimalChildEnvironment `
            -AllowedNames @(
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "WINDIR",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_CONFIG_GLOBAL",
                "GIT_OPTIONAL_LOCKS",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "XDG_CONFIG_HOME"
            ) `
            -ScriptBlock {
                & $git `
                    -c "core.fsmonitor=false" `
                    -c "core.hooksPath=NUL" `
                    @Arguments
            }
        $exitCode = $LASTEXITCODE
        return $result
    } finally {
        foreach ($name in $controlledNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $snapshot[$name],
                "Process"
            )
        }
        if ($null -ne $exitCode) {
            $global:LASTEXITCODE = $exitCode
        }
        $snapshot.Clear()
        $config = $null
    }
}

function Test-C9GitWorktreeClean {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    [void](Invoke-C9Git -Arguments @(
        "-C",
        $RepositoryRoot,
        "diff",
        "--quiet",
        "--ignore-submodules=none",
        "--"
    ))
    $unstagedExit = $LASTEXITCODE
    if ($unstagedExit -gt 1) {
        throw "Unable to inspect unstaged C9 changes."
    }
    [void](Invoke-C9Git -Arguments @(
        "-C",
        $RepositoryRoot,
        "diff",
        "--cached",
        "--quiet",
        "--ignore-submodules=none",
        "--"
    ))
    $stagedExit = $LASTEXITCODE
    if ($stagedExit -gt 1) {
        throw "Unable to inspect staged C9 changes."
    }
    $untracked = @(
        Invoke-C9Git -Arguments @(
            "-C",
            $RepositoryRoot,
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory"
        )
    )
    $untrackedExit = $LASTEXITCODE
    if ($untrackedExit -ne 0) {
        throw "Unable to inspect untracked C9 changes."
    }
    $clean = (
        $unstagedExit -eq 0 -and
        $stagedExit -eq 0 -and
        $untracked.Count -eq 0
    )
    $untracked = $null
    return $clean
}

function Assert-C9GitState {
    param([switch]$AllowDirty)

    $root = Get-C9RepositoryRoot
    Assert-C9GitInvocationBoundary
    $branch = (
        @(
            Invoke-C9Git -Arguments @(
                "-C",
                $root,
                "branch",
                "--show-current"
            )
        ) -join "`n"
    ).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C9Branch) {
        throw "C9 protected runtime requires branch $script:C9Branch; observed '$branch'."
    }
    [void](Invoke-C9Git -Arguments @(
        "-C",
        $root,
        "merge-base",
        "--is-ancestor",
        $script:C9AcceptedC8Commit,
        "HEAD"
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "C9 protected runtime does not descend from accepted C8."
    }
    if (-not $AllowDirty -and -not (Test-C9GitWorktreeClean -RepositoryRoot $root)) {
        throw "C9 protected runtime requires a clean worktree."
    }
}

function Get-C9BuildCommit {
    Assert-C9GitInvocationBoundary
    $commit = (
        @(
            Invoke-C9Git -Arguments @(
                "-C",
                (Get-C9RepositoryRoot),
                "rev-parse",
                "HEAD"
            )
        ) -join "`n"
    ).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
        throw "Unable to resolve a full lowercase C9 build commit."
    }
    return $commit
}

function Assert-C9SecretEnvironment {
    $names = @(
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
        "SLG_C9_CONTROL_TOKEN"
    )
    $values = @{}
    foreach ($name in $names) {
        $value = [Environment]::GetEnvironmentVariable($name, "Process")
        $bytes = $null
        if (
            [string]::IsNullOrWhiteSpace($value) -or
            $value -cnotmatch "^[A-Za-z0-9+/]{43}=$"
        ) {
            throw "$name must be canonical Base64 for exactly 32 random bytes."
        }
        try {
            $bytes = [Convert]::FromBase64String($value)
            if (
                $bytes.Length -ne 32 -or
                [Convert]::ToBase64String($bytes) -cne $value
            ) {
                throw "$name is not a canonical 32-byte process secret."
            }
        } catch {
            throw "$name must be canonical Base64 for exactly 32 random bytes."
        } finally {
            if ($null -ne $bytes) {
                [Array]::Clear($bytes, 0, $bytes.Length)
            }
        }
        $values[$name] = $value
    }
    for ($left = 0; $left -lt $names.Count; $left++) {
        for ($right = $left + 1; $right -lt $names.Count; $right++) {
            if ($values[$names[$left]] -ceq $values[$names[$right]]) {
                throw "C9 process secrets must be pairwise independent."
            }
        }
    }
}

function Initialize-C9ProcessSecrets {
    $names = @(
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
        "SLG_C9_CONTROL_TOKEN"
    )
    $generated = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::Ordinal
    )
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    try {
        foreach ($name in $names) {
            $value = $null
            for ($attempt = 0; $attempt -lt 16; $attempt++) {
                $candidate = $null
                $bytes = [byte[]]::new(32)
                $rng = $null
                try {
                    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                    $rng.GetBytes($bytes)
                    $candidate = [Convert]::ToBase64String($bytes)
                } finally {
                    [Array]::Clear($bytes, 0, $bytes.Length)
                    if ($null -ne $rng) {
                        $rng.Dispose()
                    }
                }
                if ($generated.Add($candidate)) {
                    $value = $candidate
                    break
                }
                $candidate = $null
            }
            if ($null -eq $value) {
                throw "C9 could not generate four independent process secrets."
            }
            [Environment]::SetEnvironmentVariable(
                $name,
                $value,
                "Process"
            )
            $value = $null
        }
        Assert-C9SecretEnvironment
        return $names
    } catch {
        foreach ($name in $names) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        throw
    } finally {
        $generated.Clear()
    }
}

function Assert-C9AuditKeyEnvironment {
    $value = [Environment]::GetEnvironmentVariable("SLG_AUDIT_KEY", "Process")
    if (
        [string]::IsNullOrWhiteSpace($value) -or
        $value.Length -lt 32 -or
        $value.Length -gt 512
    ) {
        throw "SLG_AUDIT_KEY must remain available for C9 evidence verification."
    }
}

function Assert-C9LocalAIEnvironment {
    $endpoint = [Environment]::GetEnvironmentVariable(
        "SLG_C9_LOCAL_AI_ENDPOINT",
        "Process"
    )
    if ([string]::IsNullOrWhiteSpace($endpoint)) {
        throw "SLG_C9_LOCAL_AI_ENDPOINT is missing from the process environment."
    }
    $match = [regex]::Match(
        $endpoint,
        "^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})/v1/chat/completions$",
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $port = 0
    if (
        -not $match.Success -or
        -not [int]::TryParse($match.Groups[1].Value, [ref]$port) -or
        $port -gt 65535
    ) {
        throw (
            "SLG_C9_LOCAL_AI_ENDPOINT must be exact literal IPv4 loopback " +
            "http://127.0.0.1:<port>/v1/chat/completions."
        )
    }

    $model = [Environment]::GetEnvironmentVariable(
        "SLG_C9_LOCAL_AI_MODEL",
        "Process"
    )
    if (
        [string]::IsNullOrWhiteSpace($model) -or
        $model.Length -gt 128 -or
        $model -cne $model.Trim()
    ) {
        throw "SLG_C9_LOCAL_AI_MODEL must be a bounded non-empty model label."
    }
    foreach ($character in $model.ToCharArray()) {
        if ([int]$character -lt 32) {
            throw "SLG_C9_LOCAL_AI_MODEL contains a control character."
        }
    }
}

function Assert-C9LocalAIRuntimeObservationEnvironment {
    $value = [Environment]::GetEnvironmentVariable(
        "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
        "Process"
    )
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw (
            "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE is missing from " +
            "the process environment."
        )
    }
    $expected = [System.IO.Path]::GetFullPath(
        (Join-Path (Get-C9StateDirectory) "local-ai-runtime-observation.json")
    )
    $observed = [System.IO.Path]::GetFullPath($value)
    if (-not $observed.Equals(
        $expected,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C9 local-AI runtime observation must use the exact private state path."
    }
    $resolved = Assert-C9StateFile -Path $observed
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "C9 local-AI runtime observation is missing."
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -lt 2 -or
        $item.Length -gt 65536
    ) {
        throw "C9 local-AI runtime observation is not safe bounded metadata."
    }
    return $resolved
}

function Assert-C9FacadeLaunchEnvironment {
    $forbidden = @(
        Get-ChildItem Env: |
            Where-Object {
                $_.Name -match "^(?i:CONTROL_PLANE_|GIT_|PYTHON)"
            } |
            Select-Object -ExpandProperty Name
    )
    if ($forbidden.Count -ne 0) {
        throw (
            "C9 facade startup refuses ambient control-plane credentials " +
            "or Git/Python injection variables."
        )
    }
}

function Invoke-C9MinimalChildEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedNames,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    $allowed = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($name in $AllowedNames) {
        if (
            [string]::IsNullOrWhiteSpace($name) -or
            $name -cnotmatch "^[A-Z][A-Z0-9_]{0,127}$" -or
            -not $allowed.Add($name)
        ) {
            throw "C9 child environment allowlist is invalid or duplicated."
        }
    }
    $snapshot = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables("Process").GetEnumerator()) {
        $snapshot[[string]$entry.Key] = [string]$entry.Value
    }
    try {
        foreach ($name in @($snapshot.Keys)) {
            if (-not $allowed.Contains([string]$name)) {
                [Environment]::SetEnvironmentVariable(
                    [string]$name,
                    $null,
                    "Process"
                )
            }
        }
        return & $ScriptBlock
    } finally {
        foreach (
            $name in @(
                [Environment]::GetEnvironmentVariables("Process").Keys
            )
        ) {
            [Environment]::SetEnvironmentVariable(
                [string]$name,
                $null,
                "Process"
            )
        }
        foreach ($name in $snapshot.Keys) {
            [Environment]::SetEnvironmentVariable(
                [string]$name,
                [string]$snapshot[$name],
                "Process"
            )
        }
        $snapshot.Clear()
        $allowed.Clear()
    }
}

function Get-C9TrustedAclContext {
    if (
        [Environment]::OSVersion.Platform -ne
        [PlatformID]::Win32NT
    ) {
        throw "C9 trusted execution boundary requires Windows ACL verification."
    }
    $currentSid = (
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).User.Value
    $trusted = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($sid in @(
        $currentSid,
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-3-0",
        "S-1-3-4",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )) {
        [void]$trusted.Add($sid)
    }
    return [pscustomobject]@{
        trusted_sids = $trusted
        sid_cache = @{}
        takeover_write_mask = (
            [uint64][Security.AccessControl.FileSystemRights]::Delete -bor
            [uint64][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [uint64][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [uint64][Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [uint64]0x40000000 -bor
            [uint64]0x10000000
        )
        content_write_mask = (
            [uint64][Security.AccessControl.FileSystemRights]::WriteData -bor
            [uint64][Security.AccessControl.FileSystemRights]::AppendData -bor
            [uint64][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [uint64][Security.AccessControl.FileSystemRights]::WriteAttributes
        )
    }
}

function Resolve-C9AclSid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    if ($Identity -match "^S-[0-9-]+$") {
        return $Identity
    }
    if ($Cache.ContainsKey($Identity)) {
        return [string]$Cache[$Identity]
    }
    try {
        $sid = (
            New-Object Security.Principal.NTAccount($Identity)
        ).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "C9 trusted execution boundary contains an unresolved principal."
    }
    $Cache[$Identity] = $sid
    return $sid
}

function Assert-C9TrustedExecutionObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [psobject]$AclContext,
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "C9 trusted execution boundary target is missing: $resolved"
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "C9 trusted execution boundary refuses reparse point: $resolved"
    }
    if (-not $item.PSIsContainer) {
        $linkCount = if ($null -eq $LinkCountProvider) {
            Get-C9FileLinkCount -Path $resolved
        } else {
            & $LinkCountProvider $resolved
        }
        if ([uint64]$linkCount -ne 1) {
            throw "C9 trusted execution boundary refuses hardlinked leaf: $resolved"
        }
    }
    $acl = if ($null -eq $AclProvider) {
        Get-Acl -LiteralPath $resolved
    } else {
        & $AclProvider $resolved
    }
    if ($null -eq $acl -or [string]::IsNullOrWhiteSpace([string]$acl.Owner)) {
        throw "C9 trusted execution boundary ACL is unavailable: $resolved"
    }
    $ownerSid = Resolve-C9AclSid `
        -Identity ([string]$acl.Owner) `
        -Cache $AclContext.sid_cache
    if (-not $AclContext.trusted_sids.Contains($ownerSid)) {
        throw "C9 execution target has an untrusted owner: $resolved"
    }
    $volumeRoot = [System.IO.Path]::GetPathRoot($resolved)
    $isVolumeRoot = $resolved.Equals(
        $volumeRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $dangerousMask = [uint64]$AclContext.takeover_write_mask
    if (-not $isVolumeRoot) {
        $dangerousMask = (
            $dangerousMask -bor
            [uint64]$AclContext.content_write_mask
        )
    }
    foreach ($rule in @($acl.Access)) {
        if (
            $rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow
        ) {
            continue
        }
        if (
            ($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        ) {
            continue
        }
        $ruleRights = [uint64](
            [int64]$rule.FileSystemRights -band
            [int64]0xFFFFFFFFL
        )
        if (
            (($ruleRights -band $dangerousMask) -eq 0)
        ) {
            continue
        }
        $ruleSid = Resolve-C9AclSid `
            -Identity ([string]$rule.IdentityReference) `
            -Cache $AclContext.sid_cache
        if (-not $AclContext.trusted_sids.Contains($ruleSid)) {
            throw (
                "C9 boundary is writable by another ordinary principal. " +
                "Secure or relocate the execution object: $resolved"
            )
        }
    }
    return $item
}

function Get-C9PathChain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $cursor = [System.IO.Path]::GetFullPath($Path)
    $reverse = New-Object "System.Collections.Generic.List[string]"
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $reverse.Add($cursor)
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if (
            [string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals(
                $cursor,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            break
        }
        $cursor = $parent
    }
    $result = @()
    for ($index = $reverse.Count - 1; $index -ge 0; $index--) {
        $result += $reverse[$index]
    }
    return $result
}

function Assert-C9TrustedPathChain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider
    )

    $context = Get-C9TrustedAclContext
    foreach ($entry in @(Get-C9PathChain -Path $Path)) {
        [void](Assert-C9TrustedExecutionObject `
            -Path $entry `
            -AclContext $context `
            -AclProvider $AclProvider `
            -LinkCountProvider $LinkCountProvider)
    }
}

function Get-C9PythonBaseDirectory {
    param(
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider
    )

    $configuration = [System.IO.Path]::GetFullPath(
        (Join-Path (Get-C9RepositoryRoot) ".venv\pyvenv.cfg")
    )
    [void](Assert-C9TrustedPathChain `
        -Path $configuration `
        -AclProvider $AclProvider `
        -LinkCountProvider $LinkCountProvider)
    $item = Get-Item -LiteralPath $configuration -Force
    if ($item.Length -lt 1 -or $item.Length -gt 65536) {
        throw "C9 pyvenv.cfg is outside its reviewed size boundary."
    }
    $matches = @(
        Get-Content -LiteralPath $configuration |
            Where-Object { $_ -match "^[ \t]*home[ \t]*=[ \t]*(.+?)[ \t]*$" } |
            ForEach-Object { $Matches[1] }
    )
    if (
        $matches.Count -ne 1 -or
        -not [System.IO.Path]::IsPathRooted($matches[0])
    ) {
        throw "C9 pyvenv.cfg must bind one absolute base-Python home."
    }
    $home = [System.IO.Path]::GetFullPath($matches[0])
    if (
        $home -eq [System.IO.Path]::GetPathRoot($home) -or
        -not (Test-Path -LiteralPath $home -PathType Container)
    ) {
        throw "C9 base-Python home is unavailable or impossibly broad."
    }
    return $home
}

function Invoke-C9TrustedExecutionTraversal {
    param(
        [Parameter(Mandatory = $true)]
        [psobject[]]$Roots,
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider,
        [ValidateRange(1, 100000)]
        [int]$MaximumObjects = 50000
    )

    $context = Get-C9TrustedAclContext
    $verified = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $expanded = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $count = 0
    foreach ($rootSpec in $Roots) {
        $rootPath = [System.IO.Path]::GetFullPath([string]$rootSpec.path)
        foreach ($ancestor in @(Get-C9PathChain -Path $rootPath)) {
            if ($verified.Add($ancestor)) {
                $count += 1
                if ($count -gt $MaximumObjects) {
                    throw "C9 trusted execution inventory exceeds its reviewed bound."
                }
                [void](Assert-C9TrustedExecutionObject `
                    -Path $ancestor `
                    -AclContext $context `
                    -AclProvider $AclProvider `
                    -LinkCountProvider $LinkCountProvider)
            }
        }
        if (-not [bool]$rootSpec.recurse) {
            continue
        }
        $pending = New-Object "System.Collections.Generic.Stack[string]"
        $pending.Push($rootPath)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            if ($verified.Add($current)) {
                $count += 1
                if ($count -gt $MaximumObjects) {
                    throw "C9 trusted execution inventory exceeds its reviewed bound."
                }
                [void](Assert-C9TrustedExecutionObject `
                    -Path $current `
                    -AclContext $context `
                    -AclProvider $AclProvider `
                    -LinkCountProvider $LinkCountProvider)
            }
            $currentItem = Get-Item -LiteralPath $current -Force
            if (-not $currentItem.PSIsContainer -or -not $expanded.Add($current)) {
                continue
            }
            $children = @(
                Get-ChildItem -LiteralPath $current -Force |
                    Sort-Object FullName -Descending
            )
            foreach ($child in $children) {
                $pending.Push([System.IO.Path]::GetFullPath($child.FullName))
            }
        }
    }
    return $count
}

function Assert-C9GitInvocationBoundary {
    param(
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider
    )

    $root = Get-C9RepositoryRoot
    $git = Get-C9GitExecutable
    $roots = @(
        [pscustomobject]@{
            path = Get-C9GitTrustRoot -GitExecutable $git
            recurse = $true
        },
        [pscustomobject]@{
            path = Join-Path $root ".git"
            recurse = $true
        }
    )
    [void](Invoke-C9TrustedExecutionTraversal `
        -Roots $roots `
        -AclProvider $AclProvider `
        -LinkCountProvider $LinkCountProvider)
}

function Assert-C9TrustedExecutionBoundary {
    param(
        [scriptblock]$AclProvider,
        [scriptblock]$LinkCountProvider
    )

    $root = Get-C9RepositoryRoot
    $git = Get-C9GitExecutable
    $system32 = [System.IO.Path]::GetFullPath(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    )
    $roots = @(
        [pscustomobject]@{
            path = Join-Path $root "src"
            recurse = $true
        },
        [pscustomobject]@{
            path = Join-Path $root "scripts\c9"
            recurse = $true
        },
        [pscustomobject]@{
            path = Join-Path $root "policy.c9.yaml"
            recurse = $false
        },
        [pscustomobject]@{
            path = Join-Path $root "governance\c0-tunnel-client.json"
            recurse = $false
        },
        [pscustomobject]@{
            path = Join-Path $root ".git"
            recurse = $true
        },
        [pscustomobject]@{
            path = Join-Path $root ".venv"
            recurse = $true
        },
        [pscustomobject]@{
            path = Get-C9PythonBaseDirectory `
                -AclProvider $AclProvider `
                -LinkCountProvider $LinkCountProvider
            recurse = $true
        },
        [pscustomobject]@{
            path = Get-C9GitTrustRoot -GitExecutable $git
            recurse = $true
        },
        [pscustomobject]@{
            path = Assert-C9TunnelBinary
            recurse = $false
        },
        [pscustomobject]@{
            path = $system32
            recurse = $false
        }
    )
    [void](Invoke-C9TrustedExecutionTraversal `
        -Roots $roots `
        -AclProvider $AclProvider `
        -LinkCountProvider $LinkCountProvider)
}

function Assert-C9TunnelEnvironment {
    $tunnelId = [Environment]::GetEnvironmentVariable(
        "CONTROL_PLANE_TUNNEL_ID",
        "Process"
    )
    if ($tunnelId -notmatch "^tunnel_[0-9a-f]{32}$") {
        throw "CONTROL_PLANE_TUNNEL_ID has an invalid format."
    }
    $apiKey = [Environment]::GetEnvironmentVariable(
        "CONTROL_PLANE_API_KEY",
        "Process"
    )
    if (
        [string]::IsNullOrWhiteSpace($apiKey) -or
        $apiKey.Length -lt 20 -or
        $apiKey -cne $apiKey.Trim()
    ) {
        throw "CONTROL_PLANE_API_KEY is missing from the process environment."
    }
}

function Assert-C9TunnelBinary {
    $root = Get-C9RepositoryRoot
    $manifest = Get-Content -LiteralPath (
        Join-Path $root "governance\c0-tunnel-client.json"
    ) -Raw | ConvertFrom-Json
    $binary = Join-Path $root ".systeme-local\c0\bin\tunnel-client.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "The verified C0-delivered tunnel-client binary is unavailable."
    }
    Assert-C9NotReparsePoint -Path $binary
    $actual = (
        Get-FileHash -LiteralPath $binary -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actual -ne $manifest.binary_sha256) {
        throw "Installed tunnel-client binary integrity check failed."
    }
    return $binary
}

function Get-C9Python {
    $python = Join-Path (Get-C9RepositoryRoot) ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw "The repository C9 Python environment is unavailable."
    }
    Assert-C9NotReparsePoint -Path $python
    return $python
}

function Get-C9PythonRuntimeExecutables {
    $launcher = [System.IO.Path]::GetFullPath((Get-C9Python))
    $base = [System.IO.Path]::GetFullPath(
        (Join-Path (Get-C9PythonBaseDirectory) "python.exe")
    )
    if (-not (Test-Path -LiteralPath $base -PathType Leaf)) {
        throw "The repository C9 base-Python runtime is unavailable."
    }
    Assert-C9NotReparsePoint -Path $base
    $paths = New-Object "System.Collections.Generic.HashSet[string]" (
        [System.StringComparer]::OrdinalIgnoreCase
    )
    [void]$paths.Add($launcher)
    [void]$paths.Add($base)
    return @($paths)
}

function Get-C9AdmissionDecision {
    Assert-C9AuditKeyEnvironment
    $root = Get-C9RepositoryRoot
    $admissionPath = Assert-C9StateFile -Path (
        Join-Path (Get-C9StateDirectory) "admission.json"
    )
    if (-not (Test-Path -LiteralPath $admissionPath -PathType Leaf)) {
        throw "C9 coordinator admission is missing."
    }
    $admissionInfo = Get-Item -LiteralPath $admissionPath -Force
    if ($admissionInfo.Length -lt 2 -or $admissionInfo.Length -gt 1048576) {
        throw "C9 coordinator admission exceeds its metadata-only size boundary."
    }
    $python = Get-C9Python
    $verificationCode = @'
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from systeme_local_gateway.c9_handoff_runtime import C9HandoffAdmission
from systeme_local_gateway.c9_live_cycle import verify_c9_live_cycle_bundle

try:
    admission = C9HandoffAdmission.model_validate_json(
        Path(sys.argv[1]).read_text(encoding="utf-8")
    )
    decision = verify_c9_live_cycle_bundle(
        bundle=admission.live_cycle_bundle,
        root=Path(sys.argv[2]),
        audit_key=os.environ["SLG_AUDIT_KEY"],
        evaluated_at=datetime.now(UTC),
    )
    stored = admission.admission_decision
    if (
        not stored.live_actions_allowed
        or stored.cycle_id != decision.cycle_id
        or stored.grant_id != decision.grant_id
        or stored.effective_tools != decision.effective_tools
    ):
        raise ValueError("stored C9 coordinator admission is inconsistent")
    print(decision.model_dump_json())
except Exception:
    raise SystemExit(1)
'@
    $result = & $python -c $verificationCode $admissionPath $root 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh C9 coordinator admission verification failed."
    }
    try {
        $decision = ($result -join "`n") | ConvertFrom-Json
    } catch {
        throw "Fresh C9 coordinator admission returned an invalid decision."
    }
    if (
        $decision.live_actions_allowed -ne $true -or
        $decision.effective_tool_count -ne 1 -or
        @($decision.effective_tools).Count -ne 1 -or
        $decision.effective_tools[0] -ne $script:C9ToolName -or
        $decision.c8_live_cycle_grant_reused -ne $false
    ) {
        throw "C9 admission did not preserve the exact fresh one-tool boundary."
    }
    return $decision
}

function Assert-C9LoopbackListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $matching = @(
        Get-NetTCPConnection -State Listen -OwningProcess $ProcessId `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $Port }
    )
    if ($matching.Count -ne 1) {
        throw "Expected exactly one C9 listener for PID $ProcessId on port $Port."
    }
    if ($matching[0].LocalAddress -ne "127.0.0.1") {
        throw "C9 listener is not bound to exact IPv4 loopback."
    }
}

function Write-C9ProcessRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process
    )

    $path = Assert-C9StateFile -Path (
        Join-Path (Get-C9StateDirectory) "$Name.process.json"
    )
    if (Test-Path -LiteralPath $path) {
        if (-not $Process.HasExited) {
            $Process.Kill()
            [void]$Process.WaitForExit(5000)
        }
        throw "A C9 process record already exists: $Name"
    }
    $record = [pscustomobject]@{
        version = "1"
        pid = $Process.Id
        executable_path = [System.IO.Path]::GetFullPath($Process.Path)
        start_time_utc_ticks = $Process.StartTime.ToUniversalTime().Ticks
    }
    $temporary = Assert-C9StateFile -Path (
        $path + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    )
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText(
            $temporary,
            ($record | ConvertTo-Json -Compress),
            $encoding
        )
        [System.IO.File]::Move($temporary, $path)
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        if (-not $Process.HasExited) {
            $Process.Kill()
            [void]$Process.WaitForExit(5000)
        }
        throw
    }
}

function Read-C9ProcessRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $path = Assert-C9StateFile -Path (
        Join-Path (Get-C9StateDirectory) "$Name.process.json"
    )
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }
    $recordInfo = Get-Item -LiteralPath $path -Force
    if ($recordInfo.Length -lt 2 -or $recordInfo.Length -gt 4096) {
        throw "Invalid C9 process record: $path"
    }
    try {
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid C9 process record: $path"
    }
    $parsedPid = 0
    $parsedTicks = 0L
    if (
        $record.version -ne "1" -or
        -not [int]::TryParse([string]$record.pid, [ref]$parsedPid) -or
        $parsedPid -lt 1 -or
        -not [long]::TryParse(
            [string]$record.start_time_utc_ticks,
            [ref]$parsedTicks
        ) -or
        $parsedTicks -lt 1 -or
        -not [System.IO.Path]::IsPathRooted([string]$record.executable_path)
    ) {
        throw "Invalid C9 process record: $path"
    }
    return [pscustomobject]@{
        path = $path
        pid = $parsedPid
        executable_path = [System.IO.Path]::GetFullPath(
            [string]$record.executable_path
        )
        start_time_utc_ticks = $parsedTicks
    }
}

function Read-C9Pid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $record = Read-C9ProcessRecord -Name $Name
    if ($null -eq $record) {
        return $null
    }
    return $record.pid
}

function Stop-C9Process {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedExecutablePaths
    )

    $record = Read-C9ProcessRecord -Name $Name
    if ($null -eq $record) {
        return
    }
    $allowed = @(
        $AllowedExecutablePaths |
            ForEach-Object { [System.IO.Path]::GetFullPath($_) }
    )
    if (-not ($allowed -contains $record.executable_path)) {
        throw "Refusing an unexpected recorded executable for C9 $Name."
    }
    $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $actualPath = [System.IO.Path]::GetFullPath($process.Path)
        $actualTicks = $process.StartTime.ToUniversalTime().Ticks
        if (
            -not ($allowed -contains $actualPath) -or
            $actualPath -ne $record.executable_path -or
            $actualTicks -ne $record.start_time_utc_ticks
        ) {
            throw "Refusing to stop a process not owned by the C9 process record."
        }
        Stop-Process -Id $record.pid
        Wait-Process -Id $record.pid -Timeout 15 -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $record.path -Force -ErrorAction SilentlyContinue
}

function Stop-C9PythonLauncher {
    $record = Read-C9ProcessRecord -Name "facade-launcher"
    if ($null -eq $record) {
        return
    }
    $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $record.path -Force -ErrorAction SilentlyContinue
        return
    }
    Wait-Process -Id $record.pid -Timeout 5 -ErrorAction SilentlyContinue
    if ($null -ne (Get-Process -Id $record.pid -ErrorAction SilentlyContinue)) {
        Stop-C9Process -Name "facade-launcher" `
            -AllowedExecutablePaths @((Get-C9Python))
    } else {
        Remove-Item -LiteralPath $record.path -Force -ErrorAction SilentlyContinue
    }
}

function ConvertFrom-C9Utf8Base64 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$FieldName,
        [ValidateRange(1, 12288)]
        [int]$MaximumBytes = 4096
    )

    $bytes = $null
    $decoded = $null
    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value.Length -gt 16384 -or
        $Value -notmatch "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    ) {
        throw "$FieldName must be strict bounded Base64."
    }
    try {
        $bytes = [Convert]::FromBase64String($Value)
        if ($bytes.Length -lt 1 -or $bytes.Length -gt $MaximumBytes) {
            throw "$FieldName exceeds its UTF-8 byte boundary."
        }
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $decoded = $encoding.GetString($bytes)
    } catch {
        throw "$FieldName must encode strict bounded UTF-8."
    } finally {
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    if ([string]::IsNullOrWhiteSpace($decoded) -or $decoded.IndexOf([char]0) -ge 0) {
        throw "$FieldName must encode non-empty UTF-8 without NUL."
    }
    return $decoded
}

function Assert-C9ExactObjectFields {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Object,
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedFields,
        [Parameter(Mandatory = $true)]
        [string]$ObjectName
    )

    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($ExpectedFields | Sort-Object)
    if (
        $actual.Count -ne $expected.Count -or
        @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0
    ) {
        throw "$ObjectName does not contain the exact reviewed field set."
    }
}

function Read-C9PrivateJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [ValidateRange(2, 1048576)]
        [int]$MaximumBytes = 1048576
    )

    $resolved = Assert-C9StateFile -Path $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Required C9 private JSON is missing."
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Length -lt 2 -or $item.Length -gt $MaximumBytes) {
        throw "C9 private JSON is outside its reviewed size boundary."
    }
    try {
        return Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    } catch {
        throw "C9 private JSON is malformed."
    }
}

function Read-C9PrivateUtf8Text {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [ValidateRange(1, 12288)]
        [int]$MaximumBytes = 12288
    )

    $resolved = Assert-C9StateFile -Path $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Required C9 private response file is missing."
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Length -lt 1 -or $item.Length -gt $MaximumBytes) {
        throw "C9 private response file is outside its reviewed size boundary."
    }
    $bytes = $null
    $text = $null
    try {
        $bytes = [System.IO.File]::ReadAllBytes($resolved)
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $encoding.GetString($bytes)
    } catch {
        throw "C9 private response file must contain strict UTF-8."
    } finally {
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    if ([string]::IsNullOrWhiteSpace($text) -or $text.IndexOf([char]0) -ge 0) {
        throw "C9 private response file must contain non-empty UTF-8 without NUL."
    }
    return $text
}

function Write-C9PrivateUtf8Text {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [ValidateRange(1, 12288)]
        [int]$MaximumBytes = 12288
    )

    $resolved = Assert-C9StateFile -Path $Path
    if (Test-Path -LiteralPath $resolved) {
        throw "C9 private response already exists; replay refused."
    }
    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value.IndexOf([char]0) -ge 0
    ) {
        throw "C9 private response must contain non-empty UTF-8 without NUL."
    }
    $bytes = $null
    $stream = $null
    $moved = $false
    $temporary = Assert-C9StateFile -Path (
        $resolved + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    )
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $bytes = $encoding.GetBytes($Value)
        if ($bytes.Length -lt 1 -or $bytes.Length -gt $MaximumBytes) {
            throw "C9 private response is outside its reviewed size boundary."
        }
        $stream = [System.IO.File]::Open(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::Move($temporary, $resolved)
        $moved = $true
        $item = Get-Item -LiteralPath $resolved -Force
        if (
            $item.PSIsContainer -or
            ($item.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne $bytes.Length
        ) {
            throw "C9 private response failed its post-write verification."
        }
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        if ($moved) {
            Remove-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    return $resolved
}

function Write-C9MetadataReceipt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [psobject]$Receipt,
        [switch]$AllowOverwrite
    )

    $resolved = Assert-C9StateFile -Path $Path
    if ((Test-Path -LiteralPath $resolved) -and -not $AllowOverwrite) {
        throw "C9 metadata receipt already exists; replay refused."
    }
    $json = $Receipt | ConvertTo-Json -Depth 24 -Compress
    if (
        [string]::IsNullOrWhiteSpace($json) -or
        [System.Text.Encoding]::UTF8.GetByteCount($json) -gt 1048576 -or
        $json -match '"(?:paths|response_text|observed_image_nonce|observed_document_nonce|response_text_utf8_base64)"\s*:' -or
        $json -cmatch 'C9[0-9A-F]{32}'
    ) {
        throw "C9 receipt is not metadata-only."
    }
    $temporary = Assert-C9StateFile -Path (
        $resolved + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    )
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($temporary, $json + "`n", $encoding)
        if (Test-Path -LiteralPath $resolved) {
            [System.IO.File]::Replace($temporary, $resolved, $null)
        } else {
            [System.IO.File]::Move($temporary, $resolved)
        }
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        throw
    }
    return $resolved
}

function Assert-C9Identifier {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet("handoff", "export", "sha256")]
        [string]$Kind
    )

    $pattern = switch ($Kind) {
        "handoff" { "^c9_handoff_[0-9a-f]{32}$" }
        "export" { "^c9_export_[0-9a-f]{32}$" }
        "sha256" { "^[0-9a-f]{64}$" }
    }
    if ($Value -cnotmatch $pattern) {
        throw "C9 $Kind identifier has an invalid format."
    }
    return $Value
}

function Assert-C9FreshExpiration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpiresAt,
        [Parameter(Mandatory = $true)]
        [string]$EvidenceName
    )

    $parsed = [DateTimeOffset]::MinValue
    if (
        -not [DateTimeOffset]::TryParse(
            $ExpiresAt,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed
        ) -or
        $parsed -le [DateTimeOffset]::UtcNow
    ) {
        throw "$EvidenceName is expired. Stop this cycle and create a fresh C9 handoff."
    }
    return $parsed
}

function Get-C9Utf8Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            return (
                [BitConverter]::ToString($algorithm.ComputeHash($bytes))
            ).Replace("-", "").ToLowerInvariant()
        } finally {
            $algorithm.Dispose()
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-C9NativeRuntimeProductMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$FallbackName
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    Assert-C9NotReparsePoint -Path $resolved
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "The observed local-AI executable is unavailable."
    }
    $versionInfo = (
        [System.Diagnostics.FileVersionInfo]::GetVersionInfo($resolved)
    )
    $productName = [string]$versionInfo.ProductName
    if ([string]::IsNullOrWhiteSpace($productName)) {
        $productName = $FallbackName
    }
    $productVersion = [string]$versionInfo.ProductVersion
    if ([string]::IsNullOrWhiteSpace($productVersion)) {
        $productVersion = [string]$versionInfo.FileVersion
    }
    $fallbackBinarySha256 = $null
    if ([string]::IsNullOrWhiteSpace($productVersion)) {
        $fallbackBinarySha256 = (
            Get-FileHash -LiteralPath $resolved -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($fallbackBinarySha256 -notmatch "^[0-9a-f]{64}$") {
            throw "The native local-AI binary fingerprint is unavailable."
        }
        $productVersion = "unversioned-binary-sha256:$fallbackBinarySha256"
    }
    $productName = $productName.Trim()
    $productVersion = $productVersion.Trim()
    if (
        [string]::IsNullOrWhiteSpace($productName) -or
        [string]::IsNullOrWhiteSpace($productVersion) -or
        $productName.Length -gt 128 -or
        $productVersion.Length -gt 128
    ) {
        throw "The native local-AI product metadata is outside the reviewed boundary."
    }
    return [pscustomobject]@{
        product_name = $productName
        product_version = $productVersion
        fallback_binary_sha256 = $fallbackBinarySha256
    }
}

function Get-C9SafeLocalControlHttpFailure {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $responseProperty = $ErrorRecord.Exception.PSObject.Properties["Response"]
    if ($null -eq $responseProperty -or $null -eq $responseProperty.Value) {
        return $null
    }
    $response = $responseProperty.Value
    try {
        $httpStatus = [int]$response.StatusCode
    } catch {
        return $null
    }
    if ($httpStatus -lt 400 -or $httpStatus -gt 499) {
        return $null
    }

    $failure = [ordered]@{
        http_status = $httpStatus
        api_status = $null
        reason = $null
    }
    $contentType = [string]$response.ContentType
    $message = [string]$ErrorRecord.ErrorDetails.Message
    if (
        $contentType -cnotmatch "^application/json(?:;\s*charset=utf-8)?$" -or
        [string]::IsNullOrWhiteSpace($message) -or
        $message.Length -gt 256 -or
        $message.IndexOf([char]0) -ge 0
    ) {
        return [pscustomobject]$failure
    }

    try {
        $payload = $message | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return [pscustomobject]$failure
    }
    if ($null -eq $payload -or $payload -is [array]) {
        return [pscustomobject]$failure
    }

    $expectedStatus = $null
    $expectedFields = @()
    switch ($httpStatus) {
        400 {
            $expectedStatus = "invalid_request"
            $expectedFields = @("status")
        }
        404 {
            $expectedStatus = "not_found"
            $expectedFields = @("status")
        }
        409 {
            $expectedStatus = "rejected"
            $expectedFields = @("reason", "status")
        }
        default {
            return [pscustomobject]$failure
        }
    }
    $actualFields = @($payload.PSObject.Properties.Name | Sort-Object)
    if (
        @(
            Compare-Object `
                -ReferenceObject $expectedFields `
                -DifferenceObject $actualFields
        ).Count -ne 0 -or
        [string]$payload.status -cne $expectedStatus
    ) {
        return [pscustomobject]$failure
    }

    $failure.api_status = $expectedStatus
    if ($httpStatus -eq 409) {
        $reason = [string]$payload.reason
        if ($reason -cnotmatch "^[A-Za-z][A-Za-z0-9_]{0,63}$") {
            $failure.api_status = $null
            return [pscustomobject]$failure
        }
        $failure.reason = $reason
    }
    return [pscustomobject]$failure
}

function Invoke-C9LocalControl {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "status",
            "stage",
            "approve",
            "chat/export",
            "chat/claim",
            "work/confirm",
            "chat/confirm"
        )]
        [string]$Operation,
        [ValidateSet("Get", "Post")]
        [string]$Method = "Post",
        [psobject]$Body
    )

    $facadePid = Read-C9Pid -Name "facade"
    if ($null -eq $facadePid) {
        throw "The recorded C9 facade is not running."
    }
    Assert-C9LoopbackListener -ProcessId $facadePid -Port $script:C9Port
    $controlToken = [Environment]::GetEnvironmentVariable(
        "SLG_C9_CONTROL_TOKEN",
        "Process"
    )
    if (
        [string]::IsNullOrWhiteSpace($controlToken) -or
        $controlToken.Length -lt 32 -or
        $controlToken.Length -gt 512
    ) {
        throw "SLG_C9_CONTROL_TOKEN is unavailable or invalid."
    }
    $uri = "http://127.0.0.1:$script:C9Port/_local/c9/$Operation"
    $headers = @{ Authorization = "Bearer $controlToken" }
    $bodyBytes = $null
    $json = $null
    try {
        if ($Method -eq "Get") {
            if ($null -ne $Body) {
                throw "C9 GET control requests cannot carry a body."
            }
            return Invoke-RestMethod `
                -Method Get `
                -Uri $uri `
                -Headers $headers `
                -TimeoutSec 15
        }
        if ($null -eq $Body) {
            throw "C9 POST control requests require an exact JSON object."
        }
        $json = $Body | ConvertTo-Json -Depth 12 -Compress
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        if ($bodyBytes.Length -lt 2 -or $bodyBytes.Length -gt 16384) {
            throw "C9 control request exceeds the reviewed body boundary."
        }
        return Invoke-RestMethod `
            -Method Post `
            -Uri $uri `
            -Headers $headers `
            -ContentType "application/json" `
            -Body $bodyBytes `
            -TimeoutSec 15
    } catch {
        $failure = Get-C9SafeLocalControlHttpFailure -ErrorRecord $_
        $safeDetail = ""
        if ($null -ne $failure) {
            $safeDetail = " HTTP $($failure.http_status)."
            if ($null -ne $failure.api_status) {
                $safeDetail += " API status=$($failure.api_status)."
            }
            if ($null -ne $failure.reason) {
                $safeDetail += " Reason=$($failure.reason)."
            }
        }
        throw (
            "C9 local control operation '$Operation' failed.$safeDetail " +
            "Check Get-C9Status.ps1; if evidence expired, stop and start a fresh cycle."
        )
    } finally {
        if ($null -ne $bodyBytes) {
            [Array]::Clear($bodyBytes, 0, $bodyBytes.Length)
        }
        $headers.Clear()
        $controlToken = $null
        $json = $null
    }
}

Export-ModuleMember -Function @(
    "Assert-C9ExactObjectFields",
    "Assert-C9FreshExpiration",
    "Assert-C9AuditKeyEnvironment",
    "Assert-C9GitState",
    "Assert-C9Identifier",
    "Assert-C9FacadeLaunchEnvironment",
    "Assert-C9LocalAIEnvironment",
    "Assert-C9LocalAIRuntimeObservationEnvironment",
    "Assert-C9LoopbackListener",
    "Assert-C9NotReparsePoint",
    "Assert-C9SecretEnvironment",
    "Assert-C9StateFile",
    "Assert-C9TunnelBinary",
    "Assert-C9TunnelEnvironment",
    "Assert-C9TrustedExecutionBoundary",
    "ConvertFrom-C9Utf8Base64",
    "Get-C9AdmissionDecision",
    "Get-C9BuildCommit",
    "Get-C9GitExecutable",
    "Get-C9GitGlobalConfig",
    "Get-C9NativeRuntimeProductMetadata",
    "Get-C9Python",
    "Get-C9PythonRuntimeExecutables",
    "Get-C9RepositoryRoot",
    "Get-C9StateDirectory",
    "Get-C9Utf8Sha256",
    "Initialize-C9StateDirectory",
    "Initialize-C9ProcessSecrets",
    "Invoke-C9Git",
    "Invoke-C9MinimalChildEnvironment",
    "Invoke-C9LocalControl",
    "Read-C9PrivateJson",
    "Read-C9PrivateUtf8Text",
    "Read-C9Pid",
    "Read-C9ProcessRecord",
    "Stop-C9Process",
    "Stop-C9PythonLauncher",
    "Test-C9GitWorktreeClean",
    "Write-C9MetadataReceipt",
    "Write-C9PrivateUtf8Text",
    "Write-C9ProcessRecord"
)
