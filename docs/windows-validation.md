# Windows validation

CI runs the full Rust test suite on `windows-latest`: the isolation probes in `crates/jarvis-sandbox/tests/contain.rs` (a real Python child in the worker's AppContainer tries to read the profile, write files, reach the network, start processes, open the Core's pipe and process, and use a leaked handle), the start-up check in `crates/jarvis-core/tests/isolation.rs`, the daemon tests in `crates/jarvis-core/tests/process.rs`, `jarvis-core isolation check`, and the optional provisioning script end to end. A CI runner is not a desktop, though: it runs as an administrator, inside a job, with no interactive user and nobody watching with Windows tools. This guide is the checklist for a person on a real Windows 10 or 11 machine.

Items marked **LOCAL WINDOWS VERIFICATION REQUIRED** are not proven by CI. Record what you observe in the table at the end; do not mark an item as passed without running it.

All commands are for PowerShell, from the repository root, as your **normal (non-administrator) account** unless a step says otherwise.

## 1. Toolchain and interpreter

```powershell
rustc --version          # 1.89 or newer
(Get-Command python).Source
python --version         # 3.11 or newer
```

The worker must be a real `python.exe` from a Python installation (python.org installer, per user or for all users). Not the `py` launcher, not the Microsoft Store alias in `%LOCALAPPDATA%\Microsoft\WindowsApps`, not a virtual-environment `python.exe`: each of those starts a second process, which the worker's child-process policy refuses. Set `program` in `config/jarvis.example.toml` to `"python"` if `(Get-Command python).Source` is such a `python.exe`, or to its full path.

```powershell
cargo build -p jarvis-core
$cfg = "config\jarvis.example.toml"
function jarvis { & target\debug\jarvis-core.exe @args --config $cfg }
```

## 2. Isolation check, as a normal user

**LOCAL WINDOWS VERIFICATION REQUIRED** (CI runs as an administrator).

```powershell
Measure-Command { jarvis isolation check | Out-Host }
```

Expected:

- `mechanism AppContainer (no capabilities) + job object + child-process policy + mitigations (...)`, the AppContainer name `JARVIS.Worker` and its package SID (`S-1-15-2-...`).
- `ui restrictions yes` on a normal desktop session. Record which terminal you used (Windows Terminal, conhost, VS Code); some start programs inside a job, which turns UI restrictions off.
- Two grants: read+execute on your Python directory, read on `services\intelligence-python\src`.
- Four `ok` lines: no loopback TCP, no loopback UDP, no access to the Core's files, no child processes. Exit code 0.

Record the time for a first run (it grants your Python directory to the worker's identity, which takes seconds for a large installation) and for a second run.

If Python is installed for all users outside `Program Files` and the check says it cannot grant access, run the optional provisioning once from an elevated PowerShell (section 9) and check again as a normal user.

No administrator prompt, password prompt, new account, sign-in or desktop switch may appear at any point. Record any that does.

## 3. Start the Core, check health

```powershell
target\debug\jarvis-core.exe serve --config $cfg
```

Expected: the log line `worker isolation verified` with the four checks, then `ready \\.\pipe\jarvis` on stdout. In a second PowerShell:

```powershell
jarvis health
```

Expected: `status ok`, worker `idle` with a pid, and `containment` listing the AppContainer, low integrity, privileges removed, the job object, the commit limit, the handle list, the mitigations, no child processes and the UI restriction state.

## 4. Jobs and approvals

```powershell
Measure-Command { jarvis submit "describe the runtime, then read welcome.txt" --wait }
jarvis submit "write notes.txt: remember the milk"
jarvis approvals list
jarvis approvals approve <approval-id>
```

Expected: the class A job completes. The write waits; the approval shows path, size, preview, SHA-256, capabilities, IDs, expiry and fingerprint; `var\workspace\notes.txt` does not exist until you answer `yes`; afterwards it contains `remember the milk` and `jarvis audit` shows `approval_granted`, `approval_consumed`, `execution_started`, `execution_finished`. Deny a second write and check the file is unchanged. Record the times.

## 5. The worker as Windows sees it

**LOCAL WINDOWS VERIFICATION REQUIRED.** With the Core running, open Process Explorer (Sysinternals) and select the worker `python.exe`:

- It is a child of `jarvis-core.exe` with no `conhost.exe` child.
- Security tab: **AppContainer** flag set, integrity **AppContainer** (low), package SID `S-1-15-2-...` matching section 2, no privileges except `SeChangeNotifyPrivilege`, no capabilities listed.
- Job tab: one job with active process limit 1, process memory limit 512 MiB, kill on job close, and (if `health` says so) UI restrictions.
- Handles view: the three stdio pipe handles (`\Device\NamedPipe\jarvis-worker-...`) and no handle to `jarvis.db`, `jarvis.db.lock`, the WAL file, the `\Device\NamedPipe\jarvis` RPC pipe, or any file in your profile.
- Environment tab: `PATH`, `SYSTEMROOT`, the profile variables (`APPDATA`, `HOMEDRIVE`, `HOMEPATH`, `USERPROFILE`), and `LOCALAPPDATA`, `TEMP` and `TMP`, which Windows points into `%LOCALAPPDATA%\Packages\jarvis.worker\AC` (CI observed this), and nothing else. Set `$env:JARVIS_SECRET_PROBE = "x"` before starting the Core and confirm it is absent.
- Security of `%LOCALAPPDATA%\Packages\jarvis.worker\AC` (Properties, Security, Advanced): Windows gives the package SID full control there (`icacls` shows it as `(CR)`, a critical entry). This is the one folder the worker can write. Write a file into `AC\Temp` as yourself, restart the Core, and check the file is gone: the Core empties the folder before every start.

End `jarvis-core.exe` from Task Manager (End task). Expected: the worker disappears with it.

## 6. Hostile probes on a real profile

**LOCAL WINDOWS VERIFICATION REQUIRED.** CI proves these against the runner's profile; a real profile has real files, OneDrive folders and per-user Python. Run the probe suite on your machine:

```powershell
$env:JARVIS_TEST_PYTHON = (Get-Command python).Source
cargo test -p jarvis-sandbox --test contain -- --nocapture
```

Every test must pass. They are read-only towards your files: the canaries they create live in a temporary directory and are removed, and the only directory listings attempted are of your profile, `Documents`, `Desktop`, `Downloads` and `.ssh`, which must all be refused. Then check by hand, pointing `[worker] args` in a copy of the config at a throwaway script that prints each result to stderr (the Core logs worker stderr):

- reading a file in `Documents`, `Desktop`, and a OneDrive-synced folder fails with access denied;
- reading `%APPDATA%\Microsoft\Credentials` and a browser profile directory fails;
- `socket.getaddrinfo("example.com", 443)` and `socket.create_connection(("1.1.1.1", 443), timeout=5)` fail;
- connecting to a local service you run (for example `python -m http.server 8000` in another window) fails, and that server logs no request;
- `subprocess.run(["cmd", "/c", "exit"])` fails;
- `ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, <pid of jarvis-core>)` returns 0.

## 7. Lifecycle

In the window running `serve`, press Ctrl+C once: logs show `shutdown requested`, the worker exits with code 0, the Core exits with code 0, `jarvis audit` ends with `session_closed`, `worker_exited`, `core_stopped`. Start again and press Ctrl+C twice quickly: exit code 130; the next start records recovery events. Also check `jarvis shutdown` and closing the console window.

Kill the worker (`Stop-Process -Id <worker pid> -Force`): `health` shows `restarting`, then `idle` with a new pid. Kill it more than `restart_budget` times within `restart_window_ms`: `health` reports the worker failed and `submit` is refused. Kill it while a write waits for approval: the approval becomes `expired`.

Submit a write, leave it pending, end `jarvis-core.exe` from Task Manager, start it again: `approvals list` is empty and the old approval is `expired`.

## 8. Performance

**LOCAL WINDOWS VERIFICATION REQUIRED.** CI prints its own numbers in the "Isolation overhead" step; desktop hardware, antivirus and a per-user Python change them.

```powershell
cargo test -p jarvis-sandbox --test contain -- --ignored --nocapture measure_isolation_overhead
Measure-Command { jarvis isolation check | Out-Null }     # start-up probe cost
Measure-Command { jarvis health | Out-Null }              # one RPC round trip, including CLI start
Get-Process jarvis-core, python | Select-Object Name, Id, CPU, WorkingSet64, PrivateMemorySize64
```

Record: interpreter start with and without isolation, the idle worker's memory, the start-up probe time (most of it is the 2 s the blocked loopback connection takes to give up), the `health` time, and idle CPU of both processes over a minute (it should not grow).

## 9. Optional provisioning, and removal

Normal use needs neither step. The script never starts `jarvis-core.exe` with administrator rights: it derives the worker's package SID itself.

```powershell
scripts\windows\isolation.ps1 -Action Sid                    # the package SID
scripts\windows\isolation.ps1 -Action Check -Config $cfg     # as your normal user
```

`Sid` must print the same SID as `jarvis isolation check`. `Check` refuses to run from an elevated PowerShell.

From an **elevated** PowerShell, once:

```powershell
scripts\windows\isolation.ps1 -Action Install
```

It lists what it will do and asks first: add Windows Firewall rules in the group `JARVIS worker isolation` that block all traffic for the package SID. If the isolation check failed because your Python, installed for all users outside `Program Files`, could not be granted, add `-GrantPath <python directory>`; the script refuses anything but a directory holding `python.exe` that is neither a drive root nor above `C:\Users`. Run it twice: the second run changes nothing. Check the rules in `wf.msc` (group `JARVIS worker isolation`, scoped to the package), then run `Check` again as your normal user.

To undo everything: elevated, `scripts\windows\isolation.ps1 -Action Remove [-GrantPath <python directory>]` removes the firewall rules and grants; then, as your normal user, `jarvis isolation remove` removes the Core's access entries and the AppContainer profile. Expected afterwards: no rules in the group, `icacls <python dir>` no longer lists the package SID, and `%LOCALAPPDATA%\Packages\jarvis.worker` no longer exists. A later `jarvis isolation check` recreates the profile and grants.

**LOCAL WINDOWS VERIFICATION REQUIRED:** with the Windows Defender Firewall service stopped (only on a test machine), `jarvis isolation check` must either still pass (the Filtering Platform still enforces AppContainer isolation) or fail and make the Core refuse to start. It must never report `ok` while the probe actually reached the network. Record which.

## Results

| Item | Result | Notes |
| --- | --- | --- |
| Rust and Python versions, interpreter kind | | |
| Isolation check as a normal user (first and second run time) | | |
| No prompt, account, sign-in or desktop switch | | |
| UI restrictions on a desktop session (terminal used) | | |
| Health lists the AppContainer controls | | |
| Class A job, approved write, denied write (times) | | |
| Process Explorer: AppContainer, low integrity, privileges, no capabilities | | |
| Process Explorer: job limits, no console host child | | |
| Process Explorer: only stdio handles, environment | | |
| Worker dies when the Core is ended | | |
| Probe suite on a real profile | | |
| Manual probes: Documents, OneDrive, credentials, DNS, internet, local service, child process, Core process | | |
| Ctrl+C once and twice, `shutdown`, console close | | |
| Crash, restart, budget, pending approval expiry, restart recovery | | |
| Overhead: interpreter start, idle memory, probe, RPC, idle CPU | | |
| Provisioning install twice, check, remove | | |
| Firewall service stopped (test machine only) | | |
