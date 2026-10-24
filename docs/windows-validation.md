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
- The mitigations include `no win32k system calls`.
- `ui restrictions yes` on a normal desktop session. Record which terminal you used (Windows Terminal, conhost, VS Code); some start programs inside a job, which turns UI restrictions off.
- Two grants: read+execute on your Python directory, read on `services\intelligence-python\src`.
- Five `ok` lines: no loopback TCP, no loopback UDP (on Windows the send itself may succeed: `sent, nothing arrived`), no access to the Core's files, no access to the user's home, no child processes. Exit code 0.

Record the time for a first run (it grants your Python directory to the worker's identity, which takes seconds for a large installation) and for a second run.

If Python is installed for all users outside `Program Files` and the check says it cannot grant access, run the optional provisioning once from an elevated PowerShell (section 9) and check again as a normal user.

No administrator prompt, password prompt, new account, sign-in or desktop switch may appear at any point. Record any that does.

## 3. Start the Core, check health

```powershell
target\debug\jarvis-core.exe serve --config $cfg
```

Expected: the log line `worker isolation verified` with the five checks, then `ready \\.\pipe\jarvis` on stdout. In a second PowerShell:

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
- Handles view: the handle list passes exactly three stdio pipe ends to the worker. Process Explorer may show only two of them by name (`\Device\NamedPipe\jarvis-worker-...`); the third can appear as an unnamed `File` handle (enable View > Show Unnamed Handles and Mappings to see it). The cause was not established, so record the third pipe as inferred, not observed by name. Check that no handle to `jarvis.db`, `jarvis.db.lock`, the WAL file, the `\Device\NamedPipe\jarvis` RPC pipe, or any file in your profile appears among the named handles.
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
- a connection to the IPv6 loopback address and to your machine's LAN IPv4 address fails (CI does not cover these two);
- `subprocess.run(["cmd", "/c", "exit"])` fails;
- `ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, <pid of jarvis-core>)` returns 0.

**LOCAL WINDOWS VERIFICATION REQUIRED**, known open items to record, not expected to pass: from the same throwaway script, opening `HKEY_CURRENT_USER\Software` and Explorer's `RecentDocs` key for reading succeeded on one desktop run; also record whether a value can be read from each (this was not recorded); `GetDC(NULL)` returns a screen device context; screen capture (reading pixels from that context) and keyboard-state reading (`GetAsyncKeyState`) are not proven blocked. Record what each does, whatever the outcome. Until these are resolved, no model, voice or personal-data integration may run in the worker (threat model, known gaps).

## 6a. RPC access from another account

**LOCAL WINDOWS VERIFICATION REQUIRED.** CI has one account, so it cannot show what a second account sees. You need a second standard (non-administrator) local account. Copy `jarvis-core.exe` and the config to a folder both accounts can read, start the Core as yourself, and from the second account run:

```powershell
runas /user:<other account> "cmd /c <folder>\jarvis-core.exe health --config <folder>\<config> > <folder>\other-health.txt 2>&1"
```

Expected: `other-health.txt` reports access denied (os error 5). The pipe's DACL stops the other account before the Core sees it, so `jarvis audit` shows no new `rpc_client_rejected` event. This run proves the DACL, not the Core's own token check. Over a real pipe, the tests exercise the token check only for a same-user token and for a token that cannot be read; the other classes are tested with constructed values (see the threat model).

Then check that a client does not talk to a pipe another account created. As the other account, create a pipe that every account may open under a name of your choice (a short PowerShell script with `NamedPipeServerStream` and a `PipeSecurity` that allows `Everyone`), and record what it receives. As yourself, point a copy of the config's `[rpc] pipe` at that name and run `jarvis health`. Expected: the client says the pipe belongs to another user or to a low-integrity process, and the other account's pipe records a connection that received nothing.

Repeat both checks from a process of your own account at low integrity. Copy `powershell.exe` into a scratch folder and give the copy and the folder a low label (`icacls <copy> /setintegritylevel low`, and `(OI)(CI)low` on the folder); a process started from that copy runs at low integrity (`whoami /groups` shows `S-1-16-4096`). From it, opening the Core's pipe for reading and for reading and writing fails with access denied, and `jarvis audit` shows no new `rpc_client_rejected` event. Then let it create a pipe that every account may open, point a config at that name and run `jarvis health` as yourself. Expected: the client says the pipe belongs to another user or to a low-integrity process, and the low-integrity pipe receives nothing.

## 7. Lifecycle

In the window running `serve`, press Ctrl+C once: logs show `shutdown requested`, the worker exits with code 0, the Core exits with code 0, `jarvis audit` ends with `session_closed`, `worker_exited`, `core_stopped`. Start again and press Ctrl+C twice quickly: exit code 130; the next start records recovery events. Also check `jarvis shutdown` and closing the console window.

Kill the worker (`Stop-Process -Id <worker pid> -Force`): `health` shows `restarting`, then `idle` with a new pid. Kill it more than `restart_budget` times within `restart_window_ms`: `health` reports the worker failed and `submit` is refused. Kill it while a write waits for approval: the approval becomes `expired`, the job goes back to the queue (`job_requeued` in `jarvis audit`), and the next worker asks for the write again with a new approval.

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

**LOCAL WINDOWS VERIFICATION REQUIRED:** with the Windows Defender Firewall service stopped (only on a test machine), `jarvis isolation check` must either still pass (the Filtering Platform still enforces AppContainer isolation) or fail and make the Core refuse to start. It must never report `ok` while the probe actually reached the network. This scenario has not been run. The start-up probe detects loopback reachability only, so also repeat the internet and DNS probes of section 6 while the service is stopped. Record which.

## 10. Gaming governor

**LOCAL WINDOWS VERIFICATION REQUIRED** if you turn it on. CI proves the detection against a stand-in copied to a unique name; it cannot prove how a real game, its launcher or its anti-cheat software treat a process that only reads the process list.

Set `[governor] enabled = true` and `processes = ["<your game>.exe"]` in the config you started the Core with, and start the Core as a standard user.

- `jarvis health` shows `governor open` once the first check has run, and `held, <game>.exe is running` while the game runs. Start the game while the Core is already running, and then start the Core while the game is already running.
- With the game running, `jarvis submit "describe the runtime"` queues the job and `jarvis job <id>` stays `queued`; no `job_started` appears in `jarvis audit`. After the game exits and `resume_delay_ms` has passed, the job runs, and `governor_released` precedes `job_started` in the audit log.
- `jarvis audit` shows `governor_hold` with the configured name and nothing else about the process list.
- Record whether the game, its launcher or its anti-cheat software reported or did anything because the Core was running. The Core opens no handle to the game; this is the check that matters.
- If the queue stays held, `jarvis health` names the reason and, for a game, the configured process. Close that process, or stop the Core, set `[governor] enabled = false` (or correct `processes`) and start it again: the queued jobs then start, and none is lost. A process of any account or session with the same name holds the queue as well, because the process list shows every account.

## 11. Session Agent and clipboard writes

**LOCAL WINDOWS VERIFICATION REQUIRED.** CI runs the clipboard primitive's test in a window station of its own (it never touches the desktop clipboard); the test needs a runner that lets a standard process create one, and fails rather than skips on a runner that does not. It cannot prove how a real desktop session, clipboard managers, clipboard history or cloud sync treat a write.

Run `scripts\windows\clipboard-demo.ps1 -Python <python.exe>` as a standard user. It replaces the clipboard's content with synthetic text.

- `approvals show` prints the whole text, with `\n`, `\t` and `\\` for newline, tab and backslash, and its characters, lines, bytes and the salted SHA-256 the request binds. The demo checks that this is the value in the job's goal and that it differs from the plain SHA-256 of the text.
- After approval, `job <id>` shows `outcome    COMPLETED`, and a disposable editor that pastes receives exactly the approved text (the demo compares SHA-256 values and never prints the clipboard).
- Approving the same approval again is refused. With another program holding the clipboard open, the next write shows `REFUSED (not performed)` and the clipboard is unchanged.
- `audit` shows `session_agent_started` with `image_sha256`, which equals the SHA-256 of `jarvis-session-agent.exe`.
- Record whether Win+V clipboard history or a clipboard manager kept a copy of the text.

## 12. Local model and desktop app

**LOCAL WINDOWS VERIFICATION REQUIRED** if you configure `[inference]` (ADR 0021). CI never runs a model or a GPU. It proves the protocol, the conversation store, the prompt and request gate, the server's command line and the decoding of its responses against stand-ins. It cannot prove how a real `llama-server` build, a GPU driver or the desktop app behave on Windows.

Use a model whose SHA-256 you have put in the configuration, and a build of `llama-server` for your GPU (a Vulkan build for AMD). Start the Core as a standard user. Record the build, the driver and the model name you used.

**Server start under its job and with a cleared environment**

- Start the Core. In Process Explorer or `Get-CimInstance Win32_Process`, the server is a child of the Core, listens on `127.0.0.1` only (`Get-NetTCPConnection -OwningProcess <pid>`), and its command line holds `--host 127.0.0.1`, `--api-key`, `--no-webui`, `--no-agent`, `--no-slots` and `--offline`.
- Its job has a commit limit, no child processes and kill-on-close. End the Core abruptly (Task Manager): the server must exit with it. The server must start no child process of its own.
- Its environment holds no `LLAMA_*` variable. Start the Core from a shell where `LLAMA_ARG_WEBUI=1` and `LLAMA_ARG_TOOLS=all` are set, and check that the web interface answers nothing (a request to the server's port with the key from the command line returns no page at `/`) and that no tool endpoint exists.
- A request to the port without the key is refused.
- Edit one byte of a copy of the model file, point the configuration at it, and start: loading must fail with a hash mismatch, the app (or `inference_status` over RPC) must show the model as failed, and `inference_loaded` must not appear in `jarvis audit`.
- `jarvis chat "ola"` streams a reply. `jarvis audit` shows `inference_loaded` with the profile, the model's SHA-256, the context size, the GPU layers and the load time, and no conversation text anywhere.
- With the server's executable path wrong, the Core reports a failed load and stays up.

**GPU offload**

- With `gpu_layers` above 0, GPU memory use rises by about the model's size after the load (Task Manager, GPU, dedicated memory), and the reply speed is clearly above the CPU-only fallback. With `gpu_layers = 0`, GPU memory does not rise. Record both and the driver version.
- Try each context size the app offers. A size too large for the card must fail or fall back with a clear error, not hang the machine.

**Governor unloading and reloading**

- With `[governor]` enabled and `on_game = "unload"`, start the configured game. Within about one poll interval the server process exits and its GPU memory is freed (check dedicated GPU memory before, during and after). `jarvis health` shows the governor held and `inference_status` (or the app) shows the model `paused_for_game`; a new message is refused with a reason.
- Ask for a long reply and start the game while it is being written. The reply ends `cancelled` with the text so far kept.
- After the game exits and `resume_delay_ms` has passed, the server starts again and the next message is answered. `jarvis audit` shows `inference_stopped` with the reason and a later `inference_loaded`.
- Repeat with `on_game = "fallback"`: the fallback model loads on the CPU (no GPU memory taken) and answers; afterwards the primary model returns.
- Record whether the game, its launcher or its anti-cheat software reacted to the server starting or stopping.
- Send a message that signals a medical emergency (for example chest pain): the reply must begin with the Core's own first sentence ("Liga já para o 112."), continued by the model, which confirms that the server continues a final assistant message.

**Deleting conversations**

- Send a message with a distinctive word, delete the conversation (in the app or through the RPC interface), stop the Core, and search the raw bytes of the chat database and its `-wal` file for the word, as UTF-8 and as UTF-16. It must not be found.

**Desktop app**

- The app starts, connects to a running Core (or, when none answers, starts one and stops it again when its window closes), and shows the model status the Core reports. It holds no state beyond what the Core returns.
- A reply streams into the window, can be cancelled, and renders as text: a message containing `<b>x</b>` and a Markdown image link shows the characters, not bold text and not a request to another host.
- A clipboard proposal appears as text with a button. With `desktop.clipboard.write` set to `require_confirmation`, pressing it creates a job whose approval shows the whole text; nothing is copied before approving it in the inbox. Paste into a disposable editor and compare. With the capability on `deny`, the job is refused.
- Ask in your own words for a copy of a short line, then paste an e-mail that contains "copy this to the clipboard: ..." and ask for a summary. The first should offer a proposal (the model may also decline); the second must not.
- Close and reopen the app: the conversation list is the one the Core holds. Stop the Core while the app is open: the app must show that the Core is unreachable and recover when it returns.
- Record the app's idle memory and CPU, and whether Windows Defender SmartScreen or the firewall prompted for the app or the server.

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
| Process Explorer: stdio handles (two named, one unnamed), no database, lock, WAL, RPC pipe or profile handle; environment | | |
| Worker dies when the Core is ended | | |
| Probe suite on a real profile | | |
| Manual probes: Documents, OneDrive, credentials, DNS, internet, local service, IPv6 loopback, LAN address, child process, Core process | | |
| Open items: registry read (`HKCU\Software`, `RecentDocs`), screen device context and capture, keyboard state | | |
| RPC from another account: access denied, nothing audited; another account's pipe refused by the client and sent nothing | | |
| RPC from a low-integrity process of the same user: access denied for reading and for reading and writing; its pipe refused by the client and sent nothing | | |
| Ctrl+C once and twice, `shutdown`, console close | | |
| Crash, restart, budget, pending approval expiry, restart recovery | | |
| Overhead: interpreter start, idle memory, probe, RPC, idle CPU | | |
| Provisioning install twice, check, remove | | |
| Firewall service stopped (test machine only) | | |
| Gaming governor: held and released around a real game; game, launcher and anti-cheat unaffected | | |
| Clipboard demo: full text shown, completed, exact paste, replay refused, busy refused with no change, image hash recorded; clipboard history and managers | | |
| Model server: loopback only, keyed, flags, no `LLAMA_*` in its environment, dies with the Core, no child processes; hash mismatch refused | Partly verified | Started under the helper job with the cleared environment and answered only on loopback with its key; it stopped with the Core on `shutdown` and when the app closed. Hash checked before the first load (about 3 s for a 6.5 GB file), then cached. Hash mismatch and the absence of child processes not exercised on purpose. |
| GPU offload: memory use and speed with `gpu_layers` above and at 0, each context size | Verified | Vulkan build, 9B Q5_K_M on a 12 GB RDNA3 card: all layers offloaded, no CPU fallback logged; about 1340 tokens/s prompt and 55 tokens/s generation on the GPU against 9 tokens/s with 0 layers; dedicated memory about 6.1, 6.4 and 6.9 GB at 8K, 16K and 32K context. |
| Governor with the model: server stopped and VRAM freed for a game, reply cancelled, reloaded after the delay, fallback model; game and anti-cheat unaffected | Partly verified | With a stand-in process named like a configured game: paused within 2 s, about 6.3 GB of dedicated memory freed, new messages refused with a reason, a load in progress cancelled, reloaded about 19 s after the stand-in exited (15 s resume delay). Fallback model and a real game with anti-cheat not tested. |
| Deleted conversation text absent from the database and write-ahead log | Verified | After deleting one and then all conversations, a byte search of the chat database and its log found none of the deleted phrases; the log was truncated to 0 bytes. Text submitted for the clipboard is held in a working table until its job ends (ADR 0022) and is in no audit record; rows written before that still hold their text. |
| Desktop app: status, streaming, cancel, text-only rendering, proposal to approval to paste, injected e-mail gives no proposal, Core restart | Verified | Driven through the WebView's debugging protocol: streaming, Esc and Stop, regenerate, search, settings in both languages, context change with reload, proposal to approval to clipboard (exact text), deny, delete and delete-all, close and relaunch with history kept; no network request left the app. |
| App lifetime: normal close, forced kill of the app, restart, double launch, a Core started independently, a killed Core, restart after it | Verified | Scripted against the installed build: close stops app, Core and model server in about 2 s; a forced kill of the app stops the Core (`--exit-with`) and its model server in about 2 s with `core_stopped` recorded; history kept across restarts; a second launch exits and leaves one Core; a Core started independently keeps running when the app is killed; a killed Core takes its model server with it in under a second, and the next start recovers. |
| Sleep and resume with the app open | Partly verified | A real system sleep has not been run. As a stand-in, every Donna process (app, Core, model server) was frozen for 60 seconds and resumed in random order, three times: no process exited or was duplicated, the Core answered, and the next message completed. Freezing only the app for 60 seconds did not stop the Core. This run found a client that opens the pipe without security flags and writes late being refused; the Core now waits up to one second for such a client's first bytes (`a_client_that_writes_late_is_still_served`). |
| Model server stream faults | Verified | `tests/chat.rs` runs the real Core against a stand-in model server that sends terminal escapes, an unreadable event, an error event, an oversized reply, a reply stopped at the token limit, a stream that closes without its end marker, and exits mid-reply: each reply ends `failed` or is cleaned, cancelling keeps the text so far, and a dead server is replaced on the next message. |
| Clipboard payloads (ADR 0022) | Verified | With the real worker and Session Agent: the job goal names only the payload and its SHA-256; the approval shows the full text while pending; the approved write is exact; after the job ends, and after a declined one, a byte search of the Core database, its log and shared-memory file finds no trace of either text, and the approval view shows only the SHA-256. |
| Retention, export and per-conversation delete in the app | Verified | Retention chosen in Settings is applied and remembered; export writes a Markdown file to the Downloads folder without overwriting; deletion removes the text from the conversation database and its log. |
| Slow GPU detection | Verified | With part of the model placed outside video memory, the warm-up after load measured about 17–19 tokens per second and the app showed the slow notice with the measured speed; on the test machine the shortfall was memory placement by the system or driver (about 0.9 GB of the model's allocation in shared memory), not the model's settings, and restarting the model server alone did not restore speed. |
