<#
.SYNOPSIS
    Check, harden or remove the JARVIS worker's isolation on Windows.

.DESCRIPTION
    The worker runs in an AppContainer that the Core creates for the current
    user, with no administrator rights. Normal use needs nothing from this
    script. It exists to:

      Sid      Print the worker's package SID (derived from the AppContainer
               name, as the Core derives it). No administrator rights.

      Check    As your normal user: run the Core's own isolation probe and
               report the Windows services that enforce AppContainer network
               isolation and any optional firewall rules. Refuses to run
               elevated: it starts jarvis-core.exe, which must never run with
               administrator rights.

      Install  Elevated, optional, once. Adds Windows Firewall rules that
               block all traffic for the worker's package SID, as defence in
               depth. With -GrantPath, also grants read and execute on an
               interpreter directory the user may not change (a Python
               installed for all users outside Program Files). Never starts
               jarvis-core.exe.

      Remove   Elevated: removes the firewall rules and the -GrantPath
               entries. As your normal user: runs 'jarvis-core isolation
               remove', which removes the access entries the Core made and
               the AppContainer profile.

    Every privileged action is listed and confirmed before it is performed
    (unless -Yes is given). The script stops at the first error. Running it
    again is safe.

.EXAMPLE
    scripts\windows\isolation.ps1 -Action Check -Config config\jarvis.toml

.EXAMPLE
    # From an elevated PowerShell, once (optional):
    scripts\windows\isolation.ps1 -Action Install

.EXAMPLE
    # Elevated, for a Python installed for all users in C:\Python312:
    scripts\windows\isolation.ps1 -Action Install -GrantPath C:\Python312
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Sid', 'Check', 'Install', 'Remove')]
    [string] $Action,

    # The Core configuration (Check, and Remove as a normal user).
    [string] $Config,

    # Interpreter directories to grant (Install) or ungrant (Remove).
    [string[]] $GrantPath = @(),

    # The jarvis-core executable for Check and Remove. Defaults to a release
    # build, then a debug build, in this repository.
    [string] $Core,

    # Do not ask before privileged actions.
    [switch] $Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Must match PROFILE_NAME in crates/jarvis-sandbox/src/windows/appcontainer.rs.
$ProfileName = 'JARVIS.Worker'
$RuleGroup = 'JARVIS worker isolation'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Step([string[]] $Steps) {
    Write-Host 'This will:'
    foreach ($step in $Steps) { Write-Host "  - $step" }
    if ($Yes) { return }
    $answer = Read-Host 'Continue? [y/N]'
    if ($answer -notmatch '^(y|yes)$') { throw 'Cancelled; nothing was changed.' }
}

# The package SID for the AppContainer name, computed by Windows exactly as
# the Core computes it. No executable from the repository is involved.
function Get-PackageSid {
    if (-not ('JarvisIsolation.Native' -as [type])) {
        Add-Type -Namespace JarvisIsolation -Name Native -MemberDefinition @'
[DllImport("userenv.dll", CharSet = CharSet.Unicode)]
public static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
[DllImport("advapi32.dll")]
public static extern IntPtr FreeSid(IntPtr sid);
'@
    }
    $pointer = [IntPtr]::Zero
    $result = [JarvisIsolation.Native]::DeriveAppContainerSidFromAppContainerName($ProfileName, [ref]$pointer)
    if ($result -ne 0) { throw ('DeriveAppContainerSidFromAppContainerName failed: 0x{0:X8}' -f $result) }
    try {
        $sid = (New-Object Security.Principal.SecurityIdentifier($pointer)).Value
    } finally {
        [void][JarvisIsolation.Native]::FreeSid($pointer)
    }
    if ($sid -notmatch '^S-1-15-2(-\d+){7}$') { throw "Unexpected package SID '$sid'." }
    return $sid
}

# An interpreter directory that may be granted: it exists, holds python.exe,
# and is neither a drive root nor an ancestor of the user profiles.
function Resolve-GrantPath([string] $Path) {
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\')
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw "'$full' is not a directory." }
    if (-not (Test-Path -LiteralPath (Join-Path $full 'python.exe') -PathType Leaf)) {
        throw "'$full' holds no python.exe; only an interpreter directory may be granted."
    }
    if ($full -ieq ([IO.Path]::GetPathRoot($full)).TrimEnd('\')) { throw "'$full' is a drive root." }
    $profiles = (Join-Path $env:SystemDrive 'Users').TrimEnd('\')
    if ($profiles -ieq $full -or $profiles.StartsWith("$full\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "'$full' contains the user profiles."
    }
    return $full
}

function Find-Core {
    if ($Core) { return (Resolve-Path -LiteralPath $Core).ProviderPath }
    $root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    foreach ($build in 'release', 'debug') {
        $candidate = Join-Path $root "target\$build\jarvis-core.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'jarvis-core.exe not found; build it (cargo build -p jarvis-core) or pass -Core.'
}

function Assert-Config {
    if (-not $Config) { throw "-Config is required for $Action." }
}

function Show-Services {
    # AppContainer network isolation is enforced by the Windows Filtering
    # Platform: the Base Filtering Engine (BFE) and the firewall service.
    foreach ($name in 'BFE', 'mpssvc') {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        $state = if ($service) { "$($service.Status)" } else { 'missing' }
        Write-Host ('service     {0,-8} {1}' -f $name, $state)
        if ($state -ne 'Running') {
            Write-Warning "$name is not running: AppContainer network isolation may not be enforced. The Core's start-up probe fails closed in that case."
        }
    }
}

# Callers wrap this in @(): a function that returns an empty array returns
# $null.
function Get-Rules {
    return @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
}

switch ($Action) {
    'Sid' {
        Get-PackageSid
    }

    'Check' {
        if (Test-Administrator) {
            throw 'Run Check as your normal user, not elevated: it starts jarvis-core.exe.'
        }
        Assert-Config
        & (Find-Core) isolation check --config $Config
        if ($LASTEXITCODE -ne 0) { throw "jarvis-core isolation check failed (exit code $LASTEXITCODE)." }
        Show-Services
        $rules = @(Get-Rules)
        Write-Host ('firewall    {0} optional block rule(s) for the worker' -f $rules.Count)
    }

    'Install' {
        if (-not (Test-Administrator)) {
            throw 'Install needs an elevated PowerShell (Run as administrator). Normal use does not.'
        }
        $sid = Get-PackageSid
        $grants = @($GrantPath | ForEach-Object { Resolve-GrantPath $_ })
        $rules = @(Get-Rules)

        $steps = @()
        foreach ($path in $grants) {
            $steps += "grant read and execute on '$path' (inherited) to package SID $sid"
        }
        if ($rules.Count -ne 2) {
            $steps += "add Windows Firewall rules (group '$RuleGroup') blocking all inbound and outbound traffic for package SID $sid"
        }
        if ($steps.Count -eq 0) {
            Write-Host 'Already installed; nothing to do.'
            return
        }
        Confirm-Step $steps

        foreach ($path in $grants) {
            & icacls.exe $path /grant "*${sid}:(OI)(CI)(RX)" /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls failed on '$path' (exit code $LASTEXITCODE)." }
        }
        if ($rules.Count -ne 2) {
            # Replace any partial set so the result is always the same two rules.
            $rules | Remove-NetFirewallRule
            New-NetFirewallRule -DisplayName 'JARVIS worker: block outbound' -Group $RuleGroup `
                -Direction Outbound -Action Block -Package $sid -Profile Any | Out-Null
            New-NetFirewallRule -DisplayName 'JARVIS worker: block inbound' -Group $RuleGroup `
                -Direction Inbound -Action Block -Package $sid -Profile Any | Out-Null
        }
        Write-Host 'Done. Run this script with -Action Check as your normal user to confirm.'
    }

    'Remove' {
        if (Test-Administrator) {
            $sid = Get-PackageSid
            $grants = @($GrantPath | ForEach-Object { Resolve-GrantPath $_ })
            $rules = @(Get-Rules)
            $steps = @()
            if ($rules.Count -gt 0) { $steps += "remove $($rules.Count) Windows Firewall rule(s) in group '$RuleGroup'" }
            foreach ($path in $grants) { $steps += "remove the entries for package SID $sid from '$path'" }
            if ($steps.Count -gt 0) {
                Confirm-Step $steps
                $rules | Remove-NetFirewallRule
                foreach ($path in $grants) {
                    & icacls.exe $path /remove:g "*$sid" /Q | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "icacls failed on '$path' (exit code $LASTEXITCODE)." }
                }
            } else {
                Write-Host 'No firewall rules or grants to remove.'
            }
            Write-Host 'Now run, as your normal user: jarvis-core isolation remove --config <your config>'
        } else {
            Assert-Config
            $rules = @(Get-Rules)
            & (Find-Core) isolation remove --config $Config
            if ($LASTEXITCODE -ne 0) { throw "jarvis-core isolation remove failed (exit code $LASTEXITCODE)." }
            if ($rules.Count -gt 0) {
                Write-Warning "Firewall rules in group '$RuleGroup' remain; run -Action Remove from an elevated PowerShell to remove them."
            }
        }
    }
}
