<#
.SYNOPSIS
    Demonstrate the clipboard write operation end to end with the real Core.

.DESCRIPTION
    WARNING: this demo REPLACES the current clipboard content with synthetic
    text. It uses no network. The Core and the Session Agent never read the
    clipboard; the demo reads it only as an observer, through a disposable
    editor (a hidden text box in a separate PowerShell process that pastes
    the way Ctrl+V does in a person's editor), and prints only the SHA-256
    and length of what that editor received, never the content.

    Starts a throwaway Core (its own database, workspace and RPC pipe in a
    temporary directory) with the clipboard write capability set to
    require_confirmation, and walks the operation through it:

      1. A client submits the text with the clipboard command. The Core keeps it
         as a temporary payload and the worker proposes the
         typed call desktop.write_clipboard_text, which is class B.
      2. The Core asks for approval. The request is shown as a person sees
         it: the action, the destination, the full text, its size and the
         salted SHA-256 the request binds (ADR 0022).
      3. The approval is granted for that exact fingerprint. The Session
         Agent writes the text once. The task shows outcome COMPLETED.
      4. The disposable editor pastes and reports the SHA-256 of what it
         received. It must equal the SHA-256 of the approved text.
      5. The same approval is offered again and refused.
      6. A second request is approved while another process holds the
         clipboard open. The write is refused, nothing is performed, the
         task shows outcome REFUSED (not performed) and the clipboard still
         holds the first text.
      7. A third request is denied. Nothing is performed.
      8. The audit log shows exactly one performed operation.

    Run as your normal user, in an interactive desktop session, from the
    repository root. Apart from the clipboard, nothing outside the temporary
    directory changes, except the worker's AppContainer profile, which the
    Core creates for every run.

.PARAMETER Python
    Absolute path of a python.exe (3.11+) for the worker.

.EXAMPLE
    scripts\windows\clipboard-demo.ps1 -Python C:\Python314\python.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Python
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$firstText = 'Demo: synthetic text, safe to discard'
$secondText = 'Demo: second write'
$thirdText = 'Demo: third write'

function Step([string]$text) { Write-Host "`n== $text" -ForegroundColor Cyan }

function Sha256([string]$text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

Step 'Build the Core and the Session Agent'
& cargo build --quiet --locked -p jarvis-core --bins
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$core = Join-Path $repo 'target\debug\jarvis-core.exe'

$work = Join-Path ([IO.Path]::GetTempPath()) ("jarvis-clipboard-demo-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$config = Join-Path $work 'jarvis.toml'
$pipe = 'jarvis-demo-' + (Split-Path $work -Leaf)
@"
database = 'jarvis.db'

[worker]
program = '$Python'
args = ["-m", "jarvis_worker"]
cwd = '$repo\services\intelligence-python\src'

[fixtures]
root = '$repo\tests\fixtures\files'

[workspace]
root = 'workspace'

[rpc]
pipe = '$pipe'
allow_shutdown = true

[policy]
"system.info" = "allow"
"session_agent.healthcheck" = "require_confirmation"
"desktop.clipboard.write" = "require_confirmation"
"@ | Set-Content -Encoding utf8 -Path $config
New-Item -ItemType Directory -Path (Join-Path $work 'workspace') | Out-Null

function Core([string[]]$arguments) {
    # A refusal is an expected answer here, not a script error.
    $ErrorActionPreference = 'Continue'
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        # Windows PowerShell does not escape quotes in arguments for native programs.
        $arguments = $arguments | ForEach-Object { $_ -replace '"', '\"' }
    }
    $output = & $core @arguments --config $config 2>&1 | ForEach-Object { "$_" }
    $script:status = $LASTEXITCODE
    $output
}

# The disposable editor: a hidden multiline text box in its own STA process.
# Paste() is what a person's Ctrl+V does there. Only the SHA-256 and the
# length of the received text are printed.
$editorScript = Join-Path $work 'editor-check.ps1'
@'
Add-Type -AssemblyName System.Windows.Forms
$form = New-Object System.Windows.Forms.Form
$form.ShowInTaskbar = $false
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(-32000, -32000)
$box = New-Object System.Windows.Forms.TextBox
$box.Multiline = $true
$form.Controls.Add($box)
$form.Show()
$box.Paste()
$text = $box.Text
$form.Close()
$sha = [Security.Cryptography.SHA256]::Create()
$bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
Write-Output ((-join ($bytes | ForEach-Object { $_.ToString('x2') })) + ' ' + $text.Length)
'@ | Set-Content -Encoding utf8 -Path $editorScript

function EditorReceived([string]$expectedText) {
    $line = & powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File $editorScript
    if ($LASTEXITCODE -ne 0) { throw 'the disposable editor failed' }
    $hash, $length = ("$line").Trim() -split ' '
    "editor received: sha256 $hash, $length characters"
    $same = ($hash -eq (Sha256 $expectedText)) -and ([int]$length -eq $expectedText.Length)
    "editor received exactly the approved text: $same"
    if (-not $same) { throw 'the editor did not receive the approved text' }
}

function OutcomeOfLastAgentTask {
    $line = @(Core @('tasks', '--limit', '5') | Select-String -Pattern 'desktop\.write_clipboard_text') | Select-Object -Last 1
    "$line"
}

Step 'Start the Core'
$out = Join-Path $work 'core.out'
$err = Join-Path $work 'core.err'
$serve = Start-Process -FilePath $core -ArgumentList @('serve', '--config', "`"$config`"") `
    -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -NoNewWindow
$holder = $null
try {
    $deadline = (Get-Date).AddSeconds(60)
    while (-not ((Test-Path $out) -and (Select-String -Path $out -Pattern '^ready ' -Quiet))) {
        if ($serve.HasExited -or (Get-Date) -gt $deadline) {
            Get-Content $err | Select-Object -Last 20
            throw 'the Core did not become ready'
        }
        Start-Sleep -Milliseconds 200
    }
    Get-Content $out

    Step '1. A client asks to put synthetic text on the clipboard'
    $job = (Core @('clipboard', $firstText, '--json')) | ConvertFrom-Json
    "job $($job.job_id): $($job.goal)"

    Step '2. The Core asks a person, in words'
    $pending = (Core @('approvals', 'list', '--wait', '30s', '--json')) | ConvertFrom-Json
    $approval = @($pending)[0]
    $shown = Core @('approvals', 'show', $approval.approval_id)
    $shown
    foreach ($label in 'action', 'destination', 'text', 'characters', 'sha256') {
        if (-not ($shown | Select-String -Pattern "(^|\s)$label = " -Quiet)) { throw "the approval does not show $label" }
    }
    if (-not ($shown | Select-String -SimpleMatch $firstText -Quiet)) { throw 'the approval does not show the full text' }
    # The request binds a salted SHA-256 (ADR 0022): the value in the job's
    # goal, not the plain SHA-256 of the text.
    $bound = ($job.goal -split ':')[-1]
    if ($bound -notmatch '^[0-9a-f]{64}$') { throw 'the job goal does not name a sha256' }
    if ($bound -eq (Sha256 $firstText)) { throw 'the request binds an unsalted sha256' }
    if (-not ($shown | Select-String -Pattern "(^|\s)sha256 = $bound" -Quiet)) { throw 'the approval shows a different sha256' }
    "the approval shows the full text and the salted sha256 the request binds ($bound)"

    Step '3. Approve exactly what was shown'
    Core @('approvals', 'approve', $approval.approval_id, '--fingerprint', $approval.fingerprint, '--yes')
    Core @('job', $job.job_id, '--wait', '--timeout', '60s')
    $tasks = Core @('tasks', '--limit', '5')
    $tasks
    if (-not ($tasks | Select-String -SimpleMatch 'outcome: COMPLETED' -Quiet)) { throw 'the task does not show outcome COMPLETED' }

    Step '4. A disposable editor pastes: what did it receive?'
    EditorReceived $firstText

    Step '5. The same approval cannot be used again'
    Core @('approvals', 'approve', $approval.approval_id, '--fingerprint', $approval.fingerprint, '--yes')
    if ($status -eq 0) { throw 'a consumed approval was accepted again' }
    "refused, exit code $status"

    Step '6. Another process holds the clipboard: the write is refused, not performed'
    $ready = Join-Path $work 'holder.ready'
    $holderScript = Join-Path $work 'holder.ps1'
    @"
Add-Type -Namespace Demo -Name Clip -MemberDefinition '[DllImport("user32.dll", SetLastError = true)] public static extern bool OpenClipboard(IntPtr owner); [DllImport("user32.dll", SetLastError = true)] public static extern bool CloseClipboard();'
if ([Demo.Clip]::OpenClipboard([IntPtr]::Zero)) {
    Set-Content -Path '$ready' -Value 'held'
    Start-Sleep -Seconds 25
    [void][Demo.Clip]::CloseClipboard()
} else {
    Set-Content -Path '$ready' -Value 'failed'
}
"@ | Set-Content -Encoding utf8 -Path $holderScript
    $holder = Start-Process -FilePath powershell.exe -PassThru -WindowStyle Hidden `
        -ArgumentList @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$holderScript`"")
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $ready)) {
        if ((Get-Date) -gt $deadline) { throw 'the clipboard holder did not start' }
        Start-Sleep -Milliseconds 100
    }
    if ((Get-Content $ready -Raw).Trim() -ne 'held') { throw 'the holder could not open the clipboard' }
    'another process now holds the clipboard open'

    $busy = (Core @('clipboard', $secondText, '--json')) | ConvertFrom-Json
    $second = @((Core @('approvals', 'list', '--wait', '30s', '--json')) | ConvertFrom-Json)[0]
    if ($second.approval_id -eq $approval.approval_id) { throw 'the old approval was reused' }
    Core @('approvals', 'approve', $second.approval_id, '--fingerprint', $second.fingerprint, '--yes')
    Core @('job', $busy.job_id, '--wait', '--timeout', '60s')
    $tasks = Core @('tasks', '--limit', '5')
    $tasks
    $last = OutcomeOfLastAgentTask
    if ($last -notmatch 'outcome: REFUSED \(not performed\)') { throw "expected outcome REFUSED (not performed), got: $last" }
    $refused = @(Core @('audit', '--limit', '300') | Select-String -Pattern 'session_agent_refused')
    $refused | ForEach-Object { "$_" }
    if (-not ($refused | Select-String -SimpleMatch 'clipboard_busy' -Quiet)) { throw 'no session_agent_refused with clipboard_busy was recorded' }

    # Release the holder, then check that nothing changed.
    if (-not $holder.WaitForExit(40000)) { Stop-Process -Id $holder.Id -Force }
    'the clipboard holder has released the clipboard'
    EditorReceived $firstText

    Step '7. A third request is denied'
    $third = (Core @('clipboard', $thirdText, '--json')) | ConvertFrom-Json
    $denied = @((Core @('approvals', 'list', '--wait', '30s', '--json')) | ConvertFrom-Json)[0]
    "approval $($denied.approval_id) for job $($third.job_id); denying it"
    Core @('approvals', 'deny', $denied.approval_id, '--reason', 'demo: not this one')
    Core @('job', $third.job_id, '--wait', '--timeout', '60s')
    $performed = @(Core @('audit', '--limit', '300') | Select-String -Pattern 'session_agent_completed').Count
    "Session Agent operations performed after the denial: $performed"
    if ($performed -ne 1) { throw "expected exactly one performed operation, got $performed" }
    EditorReceived $firstText

    Step '8. What was recorded'
    Core @('audit', '--limit', '300') | Select-String -Pattern 'approval_|execution_|session_agent_'
    $performed = @(Core @('audit', '--limit', '300') | Select-String -Pattern 'session_agent_completed').Count
    "Session Agent operations performed: $performed"
    if ($performed -ne 1) { throw "expected exactly one performed operation, got $performed" }
}
finally {
    Step 'Stop the Core'
    if ($holder -and -not $holder.HasExited) { Stop-Process -Id $holder.Id -Force }
    Core @('shutdown') | Out-Null
    if (-not $serve.WaitForExit(15000)) { Stop-Process -Id $serve.Id -Force }
    "work directory: $work"
}
