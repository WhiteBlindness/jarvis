# Windows validation

CI runs the full Rust test suite on `windows-latest`, including the containment probes in `crates/jarvis-sandbox/tests/contain.rs` and the daemon tests in `crates/jarvis-core/tests/process.rs`. A CI runner is not a desktop session, though: it has no interactive user, it may already place processes inside a job, and nobody looks at the result with Windows tools. This guide is the checklist for a person to run on a real Windows 10 or 11 machine.

Items marked **LOCAL WINDOWS VERIFICATION REQUIRED** are not proven by CI. Record what you observe; do not mark an item as passed without running it.

All commands are for PowerShell, from the repository root.

## 1. Toolchain

```powershell
rustc --version          # 1.89 or newer
cargo --version
(Get-Command python).Source
python --version         # 3.11 or newer
```

- Use the real interpreter in `config/jarvis.example.toml`: `program = "python"` if `(Get-Command python).Source` is a `python.exe` inside a Python installation, or its full path. Do not use the `py` launcher or the Microsoft Store alias in `%LOCALAPPDATA%\Microsoft\WindowsApps`: both start a second process, which the job object refuses (the worker may not start child processes).
- Build once: `cargo build -p jarvis-core`.

Set a helper for the rest of the guide:

```powershell
$cfg = "config\jarvis.example.toml"
function jarvis { & target\debug\jarvis-core.exe @args --config $cfg }
```

## 2. Start the Core and check health

```powershell
target\debug\jarvis-core.exe serve --config $cfg
```

Expected: the first line on stdout is `ready \\.\pipe\jarvis`, logs follow on stderr. In a second PowerShell window:

```powershell
jarvis health
```

Expected: `status ok`, worker `idle` with a pid, and `containment` listing `job object (killed with the Core, no child processes)`, `commit limit 512 MiB`, `low integrity`, `privileges removed`, and either `UI restrictions` or `no UI restrictions (already inside a job)`.

**LOCAL WINDOWS VERIFICATION REQUIRED:** on a normal desktop session the worker should not already be in a job, so `UI restrictions` should be listed. Record which one you see and from which terminal (Windows Terminal, conhost, VS Code).

## 3. Class A request

```powershell
Measure-Command { jarvis submit "describe the runtime, then read welcome.txt" --wait }
```

Expected: job `completed`, summary `2 call(s): completed=2 ...`. Record the time (this includes starting the CLI process).

## 4. Approval flow and the class B write

```powershell
jarvis submit "write notes.txt: remember the milk"
jarvis approvals list
```

Expected: one pending approval for `workspace.write_file` with `path = notes.txt`, `bytes = 17`, the preview, the SHA-256, capabilities `workspace.write`, task, request and job IDs, its age and expiry, and a fingerprint. `var\workspace\notes.txt` does not exist yet.

```powershell
jarvis approvals approve <approval-id>
```

Expected: the request is shown again and the CLI asks for `yes`. Answer anything else first and check that nothing happened (`approvals list` still shows it pending). Then approve with `yes`. `var\workspace\notes.txt` now contains `remember the milk`, the job is `completed`, and `jarvis audit` shows `approval_granted`, `approval_consumed`, `execution_started`, `execution_finished` in that order.

Repeat with `jarvis approvals deny <id>` on a second write and check the file is unchanged.

To time an approved write end to end:

```powershell
$job = (jarvis submit "write timing.txt: x" --json | ConvertFrom-Json).job_id
$id = (jarvis approvals list --wait 30s --json | ConvertFrom-Json).approval_id
Measure-Command { jarvis approvals approve $id --yes; jarvis job $job --wait }
```

## 5. Job object and process tree

**LOCAL WINDOWS VERIFICATION REQUIRED.** With the Core running, open Process Explorer (Sysinternals):

- `python.exe` (the worker) is a child of `jarvis-core.exe`, has no console host child, and its Job tab lists the job with an active process limit of 1, a process memory limit of 512 MiB, kill on job close and, if listed in `health`, the UI restrictions.
- The worker's Security tab shows integrity level **Low** and no privileges except `SeChangeNotifyPrivilege`.
- The worker's Handles view shows the three pipe handles for stdio and no handle to `jarvis.db`, `jarvis.db.lock`, `jarvis.db-wal` or the `\Device\NamedPipe\jarvis` pipe.

Then end `jarvis-core.exe` from Task Manager (End task, not Ctrl+C). Expected: the worker disappears with it.

## 6. Low integrity behaviour

**LOCAL WINDOWS VERIFICATION REQUIRED.** CI proves that a low-integrity child cannot write to `%TEMP%` and cannot open the Core's pipe (`low_integrity_cannot_write_user_files`, `the_worker_cannot_open_an_owner_only_pipe`). On a desktop also check, with a throwaway script run as the worker (for example by pointing `[worker] args` at a script that tries each action and prints the result to stderr, which the Core logs):

- writing to `%USERPROFILE%\Documents` fails with access denied;
- creating a key under `HKCU\Software` fails with access denied;
- reading a file in `%USERPROFILE%\Documents` still works (low integrity does not stop reads; this is a known gap);
- `subprocess.run(["cmd", "/c", "exit"])` fails (job process limit).

## 7. Ctrl+C and shutdown

In the window running `serve`, press Ctrl+C once. Expected: logs show `shutdown requested`, the session closes, the worker exits with code 0, and the process exits with code 0 (`$LASTEXITCODE`). `jarvis audit` ends with `session_closed`, `worker_exited`, `core_stopped`.

Start it again and press Ctrl+C twice quickly. Expected: exit code 130 without a clean shutdown; the next start records `task_recovered` or `approval_expired` events for anything left open.

Also check `jarvis shutdown` (allowed by the example config) and closing the console window.

## 8. Worker crash and restart budget

With the Core running, kill the worker from Task Manager or with `Stop-Process -Id <worker pid> -Force`. Expected: `jarvis health` shows `restarting`, then `idle` with a new pid and `restarts 1`; the audit log shows `worker_exited` and `worker_restart_scheduled`. Kill it repeatedly (more than `restart_budget` times within `restart_window_ms`): `health` reports `worker failed`, exit code 2, and `submit` is refused as `unavailable`.

Kill the worker while a write waits for approval: the approval becomes `expired` and approving it afterwards is refused.

## 9. Restart and recovery

Submit a write, leave it pending, and end `jarvis-core.exe` from Task Manager. Start the Core again. Expected: `approvals list` is empty, `approvals show <id>` says `expired`, approving it fails, and the job is `interrupted`.

## 10. Environment leak

```powershell
$env:JARVIS_SECRET_PROBE = "must-not-leak"
target\debug\jarvis-core.exe serve --config $cfg
```

CI checks the worker's environment with a probe worker (`the_worker_environment_is_cleared`): only `PATH` and `SYSTEMROOT` are passed. **LOCAL WINDOWS VERIFICATION REQUIRED:** confirm in Process Explorer (worker, Environment tab) that `JARVIS_SECRET_PROBE`, `USERPROFILE`, `APPDATA` and `TEMP` are absent.

## 11. Resource baseline

**LOCAL WINDOWS VERIFICATION REQUIRED.** With the Core idle for a minute:

```powershell
Get-Process jarvis-core, python | Select-Object Name, Id, CPU, WorkingSet64, PrivateMemorySize64
```

Record idle CPU (should not grow while idle) and memory for both processes, then the same while a job runs.

## Results

| Item | Result | Notes |
| --- | --- | --- |
| Rust and Python versions | | |
| Ready line and health | | |
| UI restrictions in a desktop session | | |
| Class A job time | | |
| Approval shown, refused without `yes`, approved with `yes` | | |
| Denied write leaves the file unchanged | | |
| Approved class B write time | | |
| Job limits, no console host child (Process Explorer) | | |
| Low integrity, privileges (Process Explorer) | | |
| Only stdio handles inherited | | |
| Worker dies when the Core is ended | | |
| Low integrity: Documents write, HKCU write, child process refused | | |
| Ctrl+C once / twice, `shutdown`, console close | | |
| Worker crash, restart, budget exhausted | | |
| Restart recovery of a pending approval | | |
| No environment leak | | |
| Idle CPU and memory | | |
