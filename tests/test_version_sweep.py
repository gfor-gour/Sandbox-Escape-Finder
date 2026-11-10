"""Version sweep: does payload Y escape on RestrictedPython version X?

Needs a *historical environment*, which cannot be assumed: point
``SEF_HISTORICAL_PYTHON`` at an interpreter that has an older RestrictedPython
installed (this repo's ``src/`` is put on PYTHONPATH automatically), e.g.::

    python -m venv .venv-rp-old
    .venv-rp-old/Scripts/pip install "RestrictedPython==<old-version>"
    set SEF_HISTORICAL_PYTHON=.venv-rp-old\\Scripts\\python.exe
    set SEF_HISTORICAL_PAYLOAD=frame_generator_inspection   (default)
    set SEF_HISTORICAL_EXPECT_ESCAPE=1                      (default)

Without ``SEF_HISTORICAL_PYTHON`` set, the historical-environment test is
skipped. The probe harness itself is always exercised against the current
interpreter, where the hardened configuration must not be escaped.

This project has not independently reproduced any particular older-version
escape; the skipped test is a template for doing so against a real pinned
environment, not a pre-filled claim about any specific release.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parent.parent / "src")

_PROBE_SCRIPT = """
import json, sys
from importlib.metadata import version
from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import DynamicProber
from sandbox_escape_finder.payloads import PAYLOADS
payload_id = sys.argv[1]
payload = next(p for p in PAYLOADS if p["id"] == payload_id)
row = DynamicProber(config=SandboxConfig(timeout_seconds=5.0)).probe_payload(payload)
print(json.dumps({
    "restrictedpython_version": version("RestrictedPython"),
    "escaped": bool(row["escaped"] or row.get("capability_recovered")),
}))
"""


def _probe(python_executable: str, payload_id: str) -> dict:
    """Run one payload through DynamicProber under `python_executable`, return its verdict."""
    env = dict(os.environ, PYTHONPATH=SRC)
    completed = subprocess.run(
        [python_executable, "-c", _PROBE_SCRIPT, payload_id],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_probe_harness_reports_version_and_hardened_config_is_safe() -> None:
    """Sanity check of the probe mechanism itself, on the current interpreter."""
    result = _probe(sys.executable, "frame_generator_inspection")
    assert result["restrictedpython_version"] == "8.5"
    assert result["escaped"] is False


@pytest.mark.skipif(
    not os.environ.get("SEF_HISTORICAL_PYTHON"),
    reason="SEF_HISTORICAL_PYTHON not set: no historical RestrictedPython environment configured",
)
def test_payload_against_historical_restrictedpython_version() -> None:
    """Probe one payload under a separately-provisioned, older RestrictedPython install.

    Only runs when the environment variable above points at a real interpreter;
    otherwise this is a documented template, not an executed assertion.
    """
    historical_python = os.environ["SEF_HISTORICAL_PYTHON"]
    payload_id = os.environ.get("SEF_HISTORICAL_PAYLOAD", "frame_generator_inspection")
    expect_escape = os.environ.get("SEF_HISTORICAL_EXPECT_ESCAPE", "1") == "1"

    result = _probe(historical_python, payload_id)
    assert result["escaped"] is expect_escape, (
        f"payload={payload_id!r} on RestrictedPython {result['restrictedpython_version']!r}: "
        f"expected escaped={expect_escape}, got {result['escaped']}"
    )
