"""Regression guard for an architectural rule: the worker asks the Core, it never acts itself.

The worker may not start processes, open sockets, load native code, touch the filesystem or run
dynamically built code. This test scans the package source for the imports and calls that would
break that rule, so a change that adds one fails here and has to be justified in review.

This is a tripwire, not a sandbox. It is a static check that a determined author can get around
(for example with ``getattr``), and it does not stop the interpreter itself from doing anything.
The enforcement point for what a worker can do is the Core, which validates every request and
applies policy; this test only keeps the worker code honest about the boundary.
"""

import ast
from pathlib import Path

import pytest

import jarvis_worker

PACKAGE_DIR = Path(jarvis_worker.__file__).resolve().parent

FORBIDDEN_MODULES = frozenset(
    {
        "subprocess",
        "socket",
        "ctypes",
        "shutil",
        "multiprocessing",
        "urllib",
        "http",
        "asyncio",
        # Dynamic imports would defeat this scan, like __import__.
        "importlib",
        # Filesystem access other than the process's own standard streams.
        "pathlib",
        "tempfile",
        "glob",
        "mmap",
        "sqlite3",
        # Other ways to reach processes, terminals, the network or the OS.
        "pty",
        "signal",
        "ssl",
        "webbrowser",
        "winreg",
        "_winapi",
        "_posixsubprocess",
    }
)
FORBIDDEN_BUILTINS = frozenset({"eval", "exec", "compile", "open", "__import__"})
FORBIDDEN_OS_FUNCTIONS = frozenset(
    {
        "system",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "startfile",
        "fork",
        "forkpty",
        "kill",
        "killpg",
        "open",
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "mkdir",
        "makedirs",
        "chmod",
        "chown",
        "truncate",
        "link",
        "symlink",
        "listdir",
        "scandir",
        "walk",
        "putenv",
        "unsetenv",
    }
)
FORBIDDEN_OS_PREFIXES = ("exec", "spawn")
# `io.FileIO` is allowed only on an existing descriptor, as in
# `io.FileIO(sys.stdout.fileno(), ...)`; given a path it opens a file.
FORBIDDEN_IO_FUNCTIONS = frozenset({"open", "open_code"})


def is_forbidden_os_function(name: str) -> bool:
    return name in FORBIDDEN_OS_FUNCTIONS or name.startswith(FORBIDDEN_OS_PREFIXES)


def violations(source: str) -> list[str]:
    """Describe every forbidden import, builtin or ``os`` function used in ``source``."""
    found: list[str] = []
    os_aliases: set[str] = set()
    io_aliases: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    found.append(f"line {node.lineno}: import {alias.name}")
                if alias.name == "os":
                    os_aliases.add(alias.asname or "os")
                if alias.name == "io":
                    io_aliases.add(alias.asname or "io")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0 and module.split(".")[0] in FORBIDDEN_MODULES:
                found.append(f"line {node.lineno}: from {module} import ...")
            if node.level == 0 and module == "os":
                found.extend(
                    f"line {node.lineno}: from os import {alias.name}"
                    for alias in node.names
                    if is_forbidden_os_function(alias.name)
                )
            if node.level == 0 and module == "io":
                found.extend(
                    f"line {node.lineno}: from io import {alias.name}"
                    for alias in node.names
                    if alias.name in FORBIDDEN_IO_FUNCTIONS | {"FileIO"}
                )
            if node.level == 0 and module == "builtins":
                found.extend(
                    f"line {node.lineno}: from builtins import {alias.name}"
                    for alias in node.names
                    if alias.name in FORBIDDEN_BUILTINS
                )
    for node in ast.walk(tree):
        # Any reference to a forbidden builtin, not only a direct call: `f = eval` is no better.
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_BUILTINS:
            found.append(f"line {node.lineno}: {node.id}")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases | {"os"}
            and is_forbidden_os_function(node.attr)
        ):
            found.append(f"line {node.lineno}: os.{node.attr}")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in io_aliases | {"io"}
            and node.attr in FORBIDDEN_IO_FUNCTIONS
        ):
            found.append(f"line {node.lineno}: io.{node.attr}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in io_aliases | {"io"}
            and node.func.attr == "FileIO"
            and not _is_fileno_call(node.args[0] if node.args else None)
        ):
            found.append(f"line {node.lineno}: io.FileIO on something other than a descriptor")
    return found


def _is_fileno_call(node: ast.expr | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fileno"
    )


def package_sources() -> list[Path]:
    return sorted(PACKAGE_DIR.rglob("*.py"))


def test_the_scan_covers_the_whole_package() -> None:
    names = {path.name for path in package_sources()}
    assert {"__init__.py", "__main__.py", "protocol.py", "client.py", "planner.py"} <= names


@pytest.mark.parametrize("path", package_sources(), ids=lambda path: path.name)
def test_the_package_has_no_forbidden_imports_or_calls(path: Path) -> None:
    assert violations(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "import subprocess as sp",
        "import socket, json",
        "import ctypes.util",
        "import shutil",
        "import multiprocessing.pool",
        "import urllib.request",
        "import http.client",
        "import asyncio",
        "import importlib",
        "from subprocess import run",
        "from urllib import request",
        "from http.client import HTTPConnection",
        "from asyncio import run",
        "from multiprocessing import Process",
        "eval('1')",
        "exec('x = 1')",
        "compile('1', 'f', 'eval')",
        "open('file')",
        "__import__('os')",
        "f = eval",
        "import os\nos.system('id')",
        "import os\nos.popen('id')",
        "import os\nos.execv('/bin/sh', [])",
        "import os\nos.execvpe('sh', [], {})",
        "import os\nos.spawnl(0, 'sh')",
        "import os as o\no.system('id')",
        "from os import system",
        "from os import popen, getcwd",
        "from os import execvp",
        "from os import spawnv",
        "from builtins import eval",
        "import pathlib",
        "from pathlib import Path",
        "import tempfile",
        "import signal",
        "import os\nos.open('x', 0)",
        "import os\nos.remove('x')",
        "import os\nos.unlink('x')",
        "import os\nos.kill(1, 9)",
        "import os\nos.fork()",
        "import os\nos.listdir('.')",
        "import os\nos.posix_spawn('sh', [], {})",
        "from os import remove",
        "import io\nio.open('x')",
        "import io as i\ni.open('x')",
        "import io\nio.FileIO('/etc/passwd')",
        "import io\nio.FileIO(path, 'rb')",
        "from io import FileIO",
        "from io import open",
    ],
)
def test_the_scan_detects_what_it_is_meant_to_forbid(source: str) -> None:
    assert violations(source) != []


@pytest.mark.parametrize(
    "source",
    [
        "import json\nimport re\nimport sys\nimport uuid",
        "import os\nos.environ",
        "import os\nos.getcwd()",
        "import re\nre.compile('x')",
        "from re import compile as build",
        "from os import getcwd",
        "from jarvis_worker.client import CoreClient",
        "from . import protocol",
        "logger.info('open the pod bay doors')",
        "import io, sys\nio.FileIO(sys.stdout.fileno(), mode='wb', closefd=False)",
        "import io\nio.BytesIO(b'x')",
    ],
)
def test_the_scan_allows_ordinary_code(source: str) -> None:
    assert violations(source) == []
