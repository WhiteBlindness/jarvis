<#
.SYNOPSIS
    Check, harden or remove the JARVIS worker's isolation on Windows.

.DESCRIPTION
    The worker runs in an AppContainer that the Core creates for the current
    user, with no administrator rights. Normal use needs nothing from this
    script. It exists to:

      Check    (no administrator rights) Run the Core's own isolation probe,
               show the worker's AppContainer identity, and report the
               Windows services that enforce AppContainer network isolation.

      Install  (administrator, optional, once) Add defence in depth:
               Windows Firewall rules that block all traffic for the worker's
               package SID, in case the AppContainer network block were ever
               not applied. Also grants the worker read and execute access to
               the interpreter's directory when the user cannot (a Python
               installed for all users outside Program Files).

      Remove   Undo everything: the firewall rules (administrator), and, by
               running 'jarvis-core isolation remove', the access entries and
               the AppContainer profile the Core created (no administrator).

    Every privileged action is listed and confirmed before it is performed
    (unless -Yes is given). The script stops at the first error and makes no
    further change. Running it again is safe.

.EXAMPLE
    scripts\windows\isolation.ps1 -Action Check -Config config\jarvis.toml

.EXAMPLE
    # From an elevated PowerShell, once:
    scripts\windows\isolation.ps1 -Action Install -Config config\jarvis.toml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Check', 'Install', 'Remove')]
    [string] $Action,

    [Parameter(Mandatory)]
    [string] $Config,

    # The jarvis-core executable. Defaults to a release build, then a debug
    # build, in this repository.
    [string] $Core,

    # Do not ask before privileged actions.
    [switch] $Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleGroup = 'JARVIS worker isolation'

function Find-Core {
    if ($Core) { return (Resolve-Path $Core).Path }
    $root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    foreach ($build in 'release', 'debug') {
        $candidate = Join-Path $root "target\$build\jarvis-core.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    throw 'jarvis-core.exe not found; build it (cargo build -p jarvis-core) or pass -Core.'
}

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

# Runs 'jarvis-core isolation check' and returns its output lines and exit
# code. The identity and grant lines are printed before the probe runs, so
# they are there even when the probe fails.
function Invoke-Check([string] $CorePath) {
    $output = @(& $CorePath isolation check --config $Config 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    return @{ Lines = $output; Code = $code }
}

function Assert-Check([string] $CorePath) {
    $result = Invoke-Check $CorePath
    if ($result.Code -ne 0) { throw "jarvis-core isolation check failed (exit code $($result.Code))." }
    return $result.Lines
}

# The paths the Core grants the worker, from the check output.
function Get-Grants([object[]] $Lines) {
    return @($Lines | Where-Object { $_ -match '^grant\s+(read\+execute|read)\s+(.+)$' } |
        ForEach-Object { $Matches[2].Trim() })
}

function Get-Field([object[]] $Lines, [string] $Name) {
    $line = $Lines | Where-Object { "$_" -like "$Name *" } | Select-Object -First 1
    if (-not $line) { throw "'$Name' missing from the isolation check output." }
    return ("$line".Substring($Name.Length)).Trim()
}

function Show-Services {
    # AppContainer network isolation is enforced by the Windows Filtering
    # Platform: the Base Filtering Engine (BFE) and the firewall service.
    foreach ($name in 'BFE', 'mpssvc') {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        $state = if ($service) { $service.Status } else { 'missing' }
        Write-Host ("service     {0,-8} {1}" -f $name, $state)
        if ($state -ne 'Running') {
            Write-Warning "$name is not running: AppContainer network isolation may not be enforced. The Core's start-up probe fails closed in that case."
        }
    }
}

function Get-Rules {
    return @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
}

$corePath = Find-Core

switch ($Action) {
    'Check' {
        $lines = Assert-Check $corePath
        Show-Services
        $rules = Get-Rules
        Write-Host ("firewall    {0} optional block rule(s) for the worker" -f $rules.Count)
    }

    'Install' {
        if (-not (Test-Administrator)) {
            throw 'Install needs an elevated PowerShell (Run as administrator). Normal use does not.'
        }
        $result = Invoke-Check $corePath
        $sid = Get-Field $result.Lines 'package sid'
        if ($sid -notmatch '^S-1-15-2(-\d+){7}$') { throw "Unexpected package SID '$sid'." }

        $steps = @()
        $grants = @()
        if ($result.Code -ne 0) {
            # Typically: the interpreter is installed for all users in a
            # directory the user may not change, so the Core could not grant
            # the worker access to it. Grant read and execute (and nothing
            # else) to the package SID on each path the Core grants.
            $grants = Get-Grants $result.Lines
            foreach ($path in $grants) {
                $steps += "grant read and execute on '$path' (inherited) to package SID $sid"
            }
        }
        $rules = Get-Rules
        if ($rules.Count -lt 2) {
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
        # Replace any partial set so the result is always the same two rules.
        $rules | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName 'JARVIS worker: block outbound' -Group $RuleGroup `
            -Direction Outbound -Action Block -Package $sid -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName 'JARVIS worker: block inbound' -Group $RuleGroup `
            -Direction Inbound -Action Block -Package $sid -Profile Any | Out-Null
        Write-Host 'Firewall rules added.'
        Assert-Check $corePath | Out-Null
    }

    'Remove' {
        $rules = Get-Rules
        $steps = @("run 'jarvis-core isolation remove': remove the worker's access entries and delete its AppContainer profile")
        if ($rules.Count -gt 0) {
            if (-not (Test-Administrator)) {
                throw "Firewall rules in group '$RuleGroup' exist; removing them needs an elevated PowerShell."
            }
            $steps += "remove $($rules.Count) Windows Firewall rule(s) in group '$RuleGroup'"
        }
        Confirm-Step $steps
        if ($rules.Count -gt 0) {
            $rules | Remove-NetFirewallRule
            Write-Host 'Firewall rules removed.'
        }
        & $corePath isolation remove --config $Config
        if ($LASTEXITCODE -ne 0) { throw "jarvis-core isolation remove failed (exit code $LASTEXITCODE)." }
    }
}
