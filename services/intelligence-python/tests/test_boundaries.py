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
    }
)
FORBIDDEN_BUILTINS = frozenset({"eval", "exec", "compile", "open", "__import__"})
FORBIDDEN_OS_FUNCTIONS = frozenset({"system", "popen"})
FORBIDDEN_OS_PREFIXES = ("exec", "spawn")


def is_forbidden_os_function(name: str) -> bool:
    return name in FORBIDDEN_OS_FUNCTIONS or name.startswith(FORBIDDEN_OS_PREFIXES)


def violations(source: str) -> list[str]:
    """Describe every forbidden import, builtin or ``os`` function used in ``source``."""
    found: list[str] = []
    os_aliases: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    found.append(f"line {node.lineno}: import {alias.name}")
                if alias.name == "os":
                    os_aliases.add(alias.asname or "os")
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
    return found


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
    ],
)
def test_the_scan_allows_ordinary_code(source: str) -> None:
    assert violations(source) == []
