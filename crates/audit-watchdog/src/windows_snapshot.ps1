$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$ProgressPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

function Get-NormalizedPath {
    param([string]$Path)

    return [System.IO.Path]::GetFullPath(
        $Path
    ).TrimEnd("\", "/").Replace("\", "/")
}

function Get-AclSnapshot {
    param(
        [string]$Path,
        [string]$Kind
    )

    $item = Get-Item `
      -LiteralPath $Path `
      -Force

    if (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "reparse point rejected: $Path"
    }

    if ($Kind -eq "directory" -and -not $item.PSIsContainer) {
        throw "directory expected: $Path"
    }
    if ($Kind -eq "file" -and $item.PSIsContainer) {
        throw "file expected: $Path"
    }

    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value

    $rules = @(
        $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ) |
        ForEach-Object {
            [pscustomobject][ordered]@{
                sid = $_.IdentityReference.Value
                rights = [int64]$_.FileSystemRights
                access_type = [string]$_.AccessControlType
                inherited = [bool]$_.IsInherited
                inheritance_flags = [int]$_.InheritanceFlags
                propagation_flags = [int]$_.PropagationFlags
            }
        } |
        Sort-Object `
          sid,
          rights,
          access_type,
          inherited,
          inheritance_flags,
          propagation_flags
    )

    return [pscustomobject][ordered]@{
        path = (Get-NormalizedPath -Path $item.FullName)
        kind = $Kind
        owner_sid = $ownerSid
        access_rules_protected = [bool]$acl.AreAccessRulesProtected
        rules = @($rules)
    }
}

function ConvertFrom-BootstrapMessage {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $lines = @(
        $Text.Replace("`r`n", "`n").Replace("`r", "`n") -split "`n" |
        ForEach-Object {
            $_.Trim()
        } |
        Where-Object {
            $_.Length -gt 0
        }
    )

    $headerIndex = -1
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if (
            $lines[$index].EndsWith(
                "Local audit anchor bootstrap",
                [System.StringComparison]::Ordinal
            )
        ) {
            $headerIndex = $index
            break
        }
    }
    if ($headerIndex -lt 0) {
        return $null
    }

    $requiredKeys = @(
        "path",
        "records",
        "last_hmac",
        "checkpoint_hmac",
        "anchor_sha256",
        "git_commit"
    )

    $values = @{}
    for (
        $index = $headerIndex + 1;
        $index -lt $lines.Count;
        $index++
    ) {
        $line = $lines[$index]
        $separator = $line.IndexOf("=")
        if ($separator -le 0) {
            continue
        }

        $key = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        if ($key -notin $requiredKeys) {
            continue
        }
        if ($values.ContainsKey($key)) {
            return $null
        }
        $values[$key] = $value
    }

    foreach ($key in $requiredKeys) {
        if (-not $values.ContainsKey($key)) {
            return $null
        }
    }

    $records = 0L
    if (-not [int64]::TryParse(
        [string]$values["records"],
        [ref]$records
    )) {
        return $null
    }

    return [pscustomobject][ordered]@{
        path = [string]$values["path"]
        records = $records
        last_hmac = [string]$values["last_hmac"]
        checkpoint_hmac = [string]$values["checkpoint_hmac"]
        anchor_sha256 = [string]$values["anchor_sha256"]
        git_commit = [string]$values["git_commit"]
    }
}

function Get-EventTextCandidates {
    param([object]$Event)

    $candidates = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]

    if (-not [string]::IsNullOrWhiteSpace([string]$Event.Message)) {
        $message = [string]$Event.Message
        if ($seen.Add($message)) {
            $candidates.Add($message)
        }
    }

    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            $text = [string]$node.'#text'
            if (
                -not [string]::IsNullOrWhiteSpace($text) -and
                $seen.Add($text)
            ) {
                $candidates.Add($text)
            }
        }
    }
    catch {
    }

    return @($candidates)
}

$projectRoot = $env:SLG_WATCHDOG_PROJECT_ROOT
if ([string]::IsNullOrWhiteSpace($projectRoot)) {
    throw "SLG_WATCHDOG_PROJECT_ROOT is unavailable"
}

$projectRoot = [System.IO.Path]::GetFullPath($projectRoot)
$stateDirectory = [System.IO.Path]::Combine(
    $projectRoot,
    ".systeme-local",
    "audit-anchor"
)
$anchorPath = [System.IO.Path]::Combine(
    $stateDirectory,
    "audit-anchor.jsonl"
)
$lockPath = "$anchorPath.lock"
$receiptPath = [System.IO.Path]::Combine(
    $stateDirectory,
    "bootstrap-receipt.json"
)
$dotenvPath = [System.IO.Path]::Combine(
    $projectRoot,
    ".env"
)

$events = @(
    Get-WinEvent `
      -FilterHashtable @{
          LogName = "Application"
          ProviderName = "SystemeLocalAuditAnchor"
          Id = 18001
      } `
      -MaxEvents 64 `
      -ErrorAction SilentlyContinue
)

$parsedEvents = @()
foreach ($event in $events) {
    $fields = $null
    foreach ($candidate in @(Get-EventTextCandidates -Event $event)) {
        $parsed = ConvertFrom-BootstrapMessage -Text $candidate
        if ($null -ne $parsed) {
            $fields = $parsed
            break
        }
    }

    if ($null -eq $fields -or $null -eq $event.TimeCreated) {
        continue
    }

    $parsedEvents += [pscustomobject][ordered]@{
        record_id = [int64]$event.RecordId
        time_created_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
        provider_name = [string]$event.ProviderName
        event_id = [int]$event.Id
        fields = $fields
    }
}

$snapshot = [pscustomobject][ordered]@{
    version = 1
    inspected_events = [int64]$events.Count
    acl = [pscustomobject][ordered]@{
        directory = Get-AclSnapshot `
          -Path $stateDirectory `
          -Kind "directory"
        anchor = Get-AclSnapshot `
          -Path $anchorPath `
          -Kind "file"
        lock = Get-AclSnapshot `
          -Path $lockPath `
          -Kind "file"
        receipt = Get-AclSnapshot `
          -Path $receiptPath `
          -Kind "file"
        dotenv = Get-AclSnapshot `
          -Path $dotenvPath `
          -Kind "file"
    }
    events = @($parsedEvents)
}

$snapshot |
  ConvertTo-Json `
    -Compress `
    -Depth 10
