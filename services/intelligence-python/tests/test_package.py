"""Package metadata stays consistent."""

import tomllib

import jarvis_worker
from jarvis_worker.protocol import validate_label
from support import PACKAGE_ROOT


def test_the_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == jarvis_worker.__version__


def test_the_version_is_a_valid_hello_label() -> None:
    assert validate_label(jarvis_worker.__version__, "worker_version")


def test_the_worker_has_no_runtime_dependencies() -> None:
    pyproject = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["dependencies"] == []
