"""Isolated dynamic probing engine for RestrictedPython sandbox validation.

This module safely executes untrusted payloads against real RestrictedPython
environments inside isolated subprocesses with strict timeouts, disposable canaries,
and automated oracle verification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandbox_escape_finder.config import SandboxConfig
    from sandbox_escape_finder.oracle import EscapeOracle, OracleVerdict


_WORKER_SCRIPT = """
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout

import RestrictedPython
from RestrictedPython import PrintCollector, compile_restricted, safe_globals
from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
from RestrictedPython.Guards import (
    full_write_guard,
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
    safer_getattr,
)

code_file = sys.argv[1]
result_file = sys.argv[2]

try:
    with open(code_file, "r", encoding="utf-8") as f:
        code = f.read()
except Exception as e:
    out = {
        "executed": False,
        "stdout": "",
        "stderr": "",
        "exception": f"PayloadReadError: {e}",
        "timed_out": False,
    }
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(out, f)
    sys.exit(0)

stdout_buf = io.StringIO()
stderr_buf = io.StringIO()
executed = False
exc_str = None

try:
    byte_code = compile_restricted(code, filename="<sandbox>", mode="exec")
except Exception as e:
    exc_str = f"{type(e).__name__}: {e}"
else:
    restricted_globals = safe_globals.copy()
    restricted_globals["_print_"] = PrintCollector
    restricted_globals["_getattr_"] = safer_getattr
    restricted_globals["_getitem_"] = default_guarded_getitem
    restricted_globals["_getiter_"] = default_guarded_getiter
    restricted_globals["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence
    restricted_globals["_unpack_sequence_"] = guarded_unpack_sequence
    restricted_globals["_write_"] = full_write_guard

    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        try:
            exec(byte_code, restricted_globals)
            executed = True
        except BaseException as e:
            executed = False
            exc_str = f"{type(e).__name__}: {e}"

    if "_print" in restricted_globals and callable(restricted_globals["_print"]):
        try:
            printed = restricted_globals["_print"]()
            if printed:
                stdout_buf.write(printed)
        except Exception:
            pass

out = {
    "executed": executed,
    "stdout": stdout_buf.getvalue(),
    "stderr": stderr_buf.getvalue(),
    "exception": exc_str,
    "timed_out": False,
}

with open(result_file, "w", encoding="utf-8") as f:
    json.dump(out, f)
"""


def sandbox_exec(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
) -> dict[str, Any]:
    """Execute code within an isolated RestrictedPython subprocess.

    Compiles code using RestrictedPython's compile_restricted, executes with
    safe_globals and standard runtime guards inside a dedicated subprocess,
    and returns a structured execution dictionary.

    Args:
        code: Python source code string to compile and execute.
        timeout: Optional execution timeout in seconds. If omitted, uses
            config.timeout_seconds if available, else defaults to 3.0 seconds.
        config: Optional SandboxConfig instance.

    Returns:
        dict[str, Any]: Execution result dictionary with keys:
            - executed (bool): True if code compiled and ran without unhandled errors.
            - stdout (str): Standard output captured during execution.
            - stderr (str): Standard error captured during execution.
            - exception (str | None): Exception message if compilation or execution failed.
            - timed_out (bool): True if execution timed out.

    Notes:
        Never raises an uncaught exception back to the caller. A crash or syntax
        error is returned as a recorded result.
    """
    effective_timeout = 3.0
    if timeout is not None:
        effective_timeout = timeout
    elif config is not None:
        effective_timeout = config.timeout_seconds

    with tempfile.TemporaryDirectory(prefix="sandbox_run_") as tmpdir:
        tmp_path = Path(tmpdir)
        code_file = tmp_path / "payload.py"
        result_file = tmp_path / "result.json"

        try:
            code_file.write_text(code, encoding="utf-8")
        except Exception as e:
            return {
                "executed": False,
                "stdout": "",
                "stderr": "",
                "exception": f"WritePayloadError: {e}",
                "timed_out": False,
            }

        try:
            proc = subprocess.run(
                [sys.executable, "-u", "-c", _WORKER_SCRIPT, str(code_file), str(result_file)],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=tmp_path,
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired:
            return {
                "executed": False,
                "stdout": "",
                "stderr": "",
                "exception": f"TimeoutExpired: Execution exceeded timeout of {effective_timeout}s",
                "timed_out": True,
            }
        except Exception as e:
            return {
                "executed": False,
                "stdout": "",
                "stderr": "",
                "exception": f"{type(e).__name__}: {e}",
                "timed_out": False,
            }

        if result_file.is_file():
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    result_data = json.load(f)
                return result_data
            except Exception as e:
                return {
                    "executed": False,
                    "stdout": proc.stdout or "",
                    "stderr": proc.stderr or "",
                    "exception": f"SerializationError: Failed to read runner output: {e}",
                    "timed_out": False,
                }
        else:
            return {
                "executed": False,
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "exception": f"ProcessTerminated: Subprocess exited with code {proc.returncode}",
                "timed_out": False,
            }


@dataclass(frozen=True)
class Payload:
    """Metadata and code for an escape attempt payload.

    Attributes:
        id: Unique identifier for the payload.
        technique: Technique category name (e.g. "subclass_traversal").
        source: Attribution source (e.g. "jailctf/pyjailbreaker", "moshekaplan").
        code: Python source code snippet of the payload.
        description: Brief description of the intended escape path.
    """

    id: str
    technique: str
    source: str
    code: str
    description: str = ""


@dataclass(frozen=True)
class ExecutionResult:
    """Raw result of running a payload in an isolated subprocess.

    Attributes:
        success: Whether the execution completed without unhandled exceptions or timeout.
        stdout: Captured standard output from the execution subprocess.
        stderr: Captured standard error from the execution subprocess.
        returncode: Exit code of the execution subprocess.
        timed_out: Whether execution was terminated due to exceeding timeout limit.
        duration_seconds: Elapsed execution duration in seconds.
        exception_info: Recorded error details if an exception crashed the sandbox.
    """

    success: bool
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    duration_seconds: float
    exception_info: str | None = None


@dataclass(frozen=True)
class ProbeReportEntry:
    """Comprehensive report entry for a single payload execution.

    Combines execution metrics with oracle ground truth for subsequent comparison
    against static analysis verdicts.

    Attributes:
        payload_id: Identifier of the tested payload.
        technique: Technique classification of the payload.
        execution: Subprocess execution metrics and output.
        oracle_verdict: Ground-truth determination of whether escape succeeded.
    """

    payload_id: str
    technique: str
    execution: ExecutionResult
    oracle_verdict: OracleVerdict


class DynamicProber:
    """Executes payloads in isolated subprocess sandboxes and records outcomes.

    Enforces mandatory process isolation, hard timeouts, disposable work directories,
    and ground-truth verification via EscapeOracle.
    """

    def __init__(self, config: SandboxConfig | None = None, oracle: EscapeOracle | None = None) -> None:
        """Initialize the prober with sandbox configuration and an optional oracle.

        Args:
            config: SandboxConfig defining timeouts, seeds, and canary parameters.
            oracle: Optional EscapeOracle instance. If None, a default instance is created.
        """
        from sandbox_escape_finder.config import load_config
        from sandbox_escape_finder.oracle import EscapeOracle

        self.config = config if config is not None else load_config()
        self.oracle = oracle if oracle is not None else EscapeOracle(self.config)

    def probe_payload(self, payload: Payload) -> ProbeReportEntry:
        """Execute a single payload in a dedicated, isolated subprocess.

        Args:
            payload: Payload specification to execute against RestrictedPython.

        Returns:
            ProbeReportEntry: Execution details and oracle verdict.
        """
        raise NotImplementedError("Stub only: isolated payload execution logic will be implemented in subsequent steps.")

    def run(self, payload_corpus: list[Payload]) -> list[ProbeReportEntry]:
        """Execute a corpus of payloads sequentially within isolated subprocesses.

        Args:
            payload_corpus: List of attributed payloads to evaluate.

        Returns:
            list[ProbeReportEntry]: Per-payload results containing execution status,
                timing, and oracle ground-truth escape verdicts.
        """
        raise NotImplementedError("Stub only: corpus probing logic will be implemented in subsequent steps.")

