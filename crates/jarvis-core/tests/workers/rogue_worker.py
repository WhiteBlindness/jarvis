"""A hostile worker used by the Core's process tests.

It speaks the protocol by hand and tries to get around the Core: smuggled
authority fields, path traversal, invented tools, replays, requests outside
its job, a denied capability, and approving its own request through the
Core's local RPC endpoint. It exits 0 only if every attempt was refused the
way the Core promises, so the Rust test can assert on both the database and
this exit code (recorded in the audit log as `worker_exited`).

Usage: rogue_worker.py MODE [RPC_ENDPOINT]

Modes:
  bypass         take one job and attempt the bypasses above; RPC_ENDPOINT is
                 the socket path (Unix) or pipe name (Windows) to attack
  env            check that the Core's environment (and, on Linux, its open
                 descriptors) did not leak into this process, then wait for
                 the Core to close the session
  crash          exit with status 7 right after the handshake
  crash-waiting  take one job, ask for a write that needs approval, then exit
                 with status 9 while the request waits for a person
  silent         never send hello
  stubborn       complete the handshake, then ignore end-of-input
"""

import json
import os
import socket
import sys
import time

failures: list[str] = []


def send(frame: dict) -> None:
    frame = {"protocol": 2, **frame}
    sys.stdout.buffer.write(json.dumps(frame).encode() + b"\n")
    sys.stdout.buffer.flush()


def recv() -> dict:
    line = sys.stdin.buffer.readline()
    if not line:
        report_and_exit("core closed the stream")
    return json.loads(line)


def report_and_exit(reason: str = "") -> None:
    if reason:
        print(f"rogue: {reason}", file=sys.stderr)
    for failure in failures:
        print(f"rogue: {failure}", file=sys.stderr)
    sys.exit(1 if failures or reason else 0)


def expect(label: str, reply: dict, **fields: object) -> None:
    for path, wanted in fields.items():
        value: object = reply
        for key in path.split("__"):
            value = value.get(key) if isinstance(value, dict) else None
        if value != wanted:
            failures.append(f"{label}: {path} = {value!r}, wanted {wanted!r}")


def handshake() -> None:
    send({"type": "hello", "worker": "rogue", "worker_version": "0"})
    expect("handshake", recv(), type="welcome")


def take_job() -> str:
    job = recv()
    expect("job", job, type="job")
    return str(job.get("job_id"))


def request(job_id: str, request_id: str, tool: str, args: object, **extra: object) -> dict:
    send(
        {
            "type": "tool_request",
            "request_id": request_id,
            "job_id": job_id,
            "tool": tool,
            "args": args,
            **extra,
        }
    )
    return recv()


def wait_for_end_of_input() -> None:
    while sys.stdin.buffer.readline():
        pass


def attack_rpc(endpoint: str) -> None:
    """Try to approve requests through the Core's client interface."""
    frame = b'{"rpc":1,"type":"list_approvals","wait_ms":0}\n'
    try:
        if os.name == "nt":
            with open(endpoint, "r+b", buffering=0) as pipe:
                pipe.write(frame)
                reply = pipe.readline()
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(10)
                conn.connect(endpoint)
                conn.sendall(frame)
                reply = conn.makefile("rb").readline()
    except OSError as error:
        print(f"rogue: RPC endpoint refused the connection: {error}", file=sys.stderr)
        return
    if not reply:
        return
    answer = json.loads(reply)
    if answer.get("type") != "error" or answer.get("code") != "forbidden":
        failures.append(f"the RPC endpoint answered the worker: {answer!r}")


def bypass(endpoint: str) -> None:
    handshake()
    job = take_job()
    reply = request(job, "r1", "system.info", {}, capabilities=["system.info"])
    expect("smuggled capabilities", reply, type="error", error__code="malformed_frame")
    reply = request(job, "r2", "workspace.write_file", {"path": "a.txt", "content": "x"}, approved=True)
    expect("smuggled approval", reply, type="error", error__code="malformed_frame")
    reply = request(
        job,
        "r3",
        "workspace.write_file",
        {"path": "a.txt", "content": "x"},
        approval_id="01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c",
    )
    expect("smuggled approval id", reply, type="error", error__code="malformed_frame")
    reply = request(job, "r4", "filesystem.read_fixture", {"path": "../../Cargo.toml"})
    expect("read traversal", reply, outcome__status="rejected", outcome__error__code="invalid_arguments")
    reply = request(job, "r5", "workspace.write_file", {"path": "../escape.txt", "content": "x"})
    expect("write traversal", reply, outcome__status="rejected", outcome__error__code="invalid_arguments")
    reply = request(job, "r6", "shell.exec", {"command": "id"})
    expect("invented tool", reply, outcome__status="rejected", outcome__error__code="unknown_tool")
    reply = request(job, "r7", "system.info", {})
    expect("denied capability", reply, outcome__status="denied")
    reply = request(job, "r7", "system.info", {})
    expect("replay", reply, type="error", error__code="duplicate_request")
    reply = request("01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b", "r8", "system.info", {})
    expect("another job", reply, type="error", error__code="unexpected_message")
    reply = request(job, "r9", "filesystem.read_fixture", {"path": "welcome.txt"})
    expect("allowed capability", reply, outcome__status="completed")

    # A write needs a person. While it waits, try to approve it ourselves.
    send(
        {
            "type": "tool_request",
            "request_id": "w1",
            "job_id": job,
            "tool": "workspace.write_file",
            "args": {"path": "rogue.txt", "content": "self-approved"},
        }
    )
    time.sleep(0.5)
    attack_rpc(endpoint)
    # The test declines the request through a real client.
    expect("approval", recv(), type="tool_response", outcome__status="declined")
    send({"type": "job_result", "job_id": job, "outcome": "completed", "summary": "done"})
    wait_for_end_of_input()


def env() -> None:
    handshake()
    # Python itself may set LC_CTYPE (PEP 538), and macOS adds one variable
    # to every process. Everything else must come from the Core's allowlist.
    allowed = {"PATH", "SYSTEMROOT", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    # Starting a Windows AppContainer needs the profile variables, and
    # Windows may point TEMP and TMP into the container's own folder.
    if os.name == "nt":
        allowed |= {"APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "USERPROFILE"}
        allowed |= {"TEMP", "TMP"}
    # Windows keeps per-drive working directories in variables named "=C:".
    leaked = sorted(
        key for key in os.environ if key.upper() not in allowed and not key.startswith("=")
    )
    if leaked:
        failures.append(f"environment leaked into the worker: {leaked}")
    # On Linux, no descriptor of the Core (database, lock file, RPC socket)
    # may be open in the worker: only stdin, stdout and stderr. Under Phase 3
    # confinement the worker cannot even read /proc, which is itself the
    # stronger guarantee; fall back to the fd scan only when /proc is open.
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        names = []
    inherited = []
    for fd in names:
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue  # the descriptor listdir itself used, now closed
        if int(fd) > 2 and not target.startswith("/proc/"):
            inherited.append(target)
    if inherited:
        failures.append(f"descriptors leaked into the worker: {inherited}")
    wait_for_end_of_input()


def crash_waiting() -> None:
    handshake()
    job = take_job()
    send(
        {
            "type": "tool_request",
            "request_id": "w1",
            "job_id": job,
            "tool": "workspace.write_file",
            "args": {"path": "never.txt", "content": "x"},
        }
    )
    time.sleep(1)
    sys.exit(9)


def main() -> None:
    mode = sys.argv[1]
    if mode == "bypass":
        bypass(sys.argv[2])
    elif mode == "env":
        env()
    elif mode == "crash":
        handshake()
        sys.exit(7)
    elif mode == "crash-waiting":
        crash_waiting()
    elif mode == "silent":
        time.sleep(60)
    elif mode == "stubborn":
        handshake()
        while True:
            time.sleep(1)
    else:
        sys.exit(f"unknown mode {mode}")
    report_and_exit()


if __name__ == "__main__":
    main()
