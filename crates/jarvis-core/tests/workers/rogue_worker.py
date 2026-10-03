"""A hostile worker used by the Core's process tests.

It speaks the protocol by hand and tries to get around the Core: smuggled
authority fields, path traversal, invented tools, replays, a denied
capability. It exits 0 only if every attempt was refused the way the Core
promises, so the Rust test can assert on both the database and this exit
code.

Modes:
  bypass  attempt the bypasses above
  env     check that the Core's environment did not leak into this process
  crash   exit with status 7 right after the handshake
  silent  never send hello
  stubborn  complete the handshake, then ignore end-of-input and keep running
"""

import json
import os
import sys
import time

failures: list[str] = []


def send(frame: dict) -> None:
    frame = {"protocol": 1, **frame}
    sys.stdout.buffer.write(json.dumps(frame).encode() + b"\n")
    sys.stdout.buffer.flush()


def recv() -> dict:
    line = sys.stdin.buffer.readline()
    if not line:
        print("rogue: core closed the stream", file=sys.stderr)
        sys.exit(1)
    return json.loads(line)


def expect(label: str, reply: dict, **fields: object) -> None:
    for path, wanted in fields.items():
        value: object = reply
        for key in path.split("__"):
            value = value.get(key) if isinstance(value, dict) else None
        if value != wanted:
            failures.append(f"{label}: {path} = {value!r}, wanted {wanted!r}")


def request(request_id: str, tool: str, args: object, **extra: object) -> dict:
    send({"type": "tool_request", "request_id": request_id, "tool": tool, "args": args, **extra})
    return recv()


def handshake() -> None:
    send({"type": "hello", "worker": "rogue", "worker_version": "0"})
    expect("handshake", recv(), type="welcome")


def bypass() -> None:
    handshake()
    reply = request("r1", "system.info", {}, capabilities=["system.info"])
    expect("smuggled capabilities", reply, type="error", error__code="malformed_frame")
    reply = request("r2", "system.info", {}, approved=True)
    expect("smuggled approval", reply, type="error", error__code="malformed_frame")
    reply = request("r3", "filesystem.read_fixture", {"path": "../../Cargo.toml"})
    expect("path traversal", reply, outcome__status="rejected", outcome__error__code="invalid_arguments")
    reply = request("r4", "shell.exec", {"command": "id"})
    expect("invented tool", reply, outcome__status="rejected", outcome__error__code="unknown_tool")
    reply = request("r5", "system.info", {})
    expect("denied capability", reply, outcome__status="denied")
    reply = request("r5", "system.info", {})
    expect("replay", reply, type="error", error__code="duplicate_request")
    reply = request("r6", "filesystem.read_fixture", {"path": "welcome.txt"})
    expect("allowed capability", reply, outcome__status="completed")


def env() -> None:
    handshake()
    # Python itself may set LC_CTYPE (PEP 538), and macOS adds one variable
    # to every process. Everything else must come from the Core's allowlist.
    allowed = {"PATH", "SYSTEMROOT", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    # Windows keeps per-drive working directories in variables named "=C:".
    leaked = sorted(
        key for key in os.environ if key.upper() not in allowed and not key.startswith("=")
    )
    if leaked:
        failures.append(f"environment leaked into the worker: {leaked}")


def main() -> None:
    mode = sys.argv[1]
    if mode == "bypass":
        bypass()
    elif mode == "env":
        env()
    elif mode == "crash":
        handshake()
        sys.exit(7)
    elif mode == "silent":
        time.sleep(60)
    elif mode == "stubborn":
        handshake()
        while True:
            time.sleep(1)
    else:
        sys.exit(f"unknown mode {mode}")

    for failure in failures:
        print(f"rogue: {failure}", file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
