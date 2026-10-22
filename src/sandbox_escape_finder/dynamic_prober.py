"""Isolated dynamic probing engine for RestrictedPython sandbox validation.

This module safely executes untrusted payloads against real RestrictedPython
environments inside isolated subprocesses with strict timeouts, disposable canaries,
and automated oracle verification.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sandbox_escape_finder.config import SandboxConfig, load_config
from sandbox_escape_finder.oracle import (
    CanaryState,
    EscapeOracle,
    OracleVerdict,
    capture_canary_state,
    oracle as default_oracle_func,
)
from sandbox_escape_finder.static_analyzer import StaticAnalyzer


_WORKER_SCRIPT = """
import ast
import builtins
import io
import json
import os
import sys
import types
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
        "capability_recovered": False,
    }
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(out, f)
    sys.exit(0)

DANGEROUS_CALLABLES = {
    eval,
    exec,
    __import__,
    open,
    compile,
}

DANGEROUS_MODULE_NAMES = {
    "os", "sys", "subprocess", "posix", "nt", "shutil", "builtins", "__builtin__", "importlib"
}

def is_dangerous(obj, depth=0, seen=None):
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen or depth > 3:
        return False
    seen.add(obj_id)

    if callable(obj) and (obj in DANGEROUS_CALLABLES or getattr(obj, "__name__", "") in ("eval", "exec", "open", "__import__", "system", "popen")):
        return True

    if isinstance(obj, types.ModuleType):
        mod_name = getattr(obj, "__name__", "")
        if mod_name in DANGEROUS_MODULE_NAMES or mod_name.startswith("os.") or mod_name.startswith("sys."):
            return True

    if isinstance(obj, types.FrameType) or hasattr(obj, "f_builtins") or (hasattr(obj, "f_globals") and hasattr(obj, "f_back")):
        return True

    if obj is getattr(builtins, "__dict__", None) or obj is builtins:
        return True

    if isinstance(obj, type):
        mod = getattr(obj, "__module__", "")
        if mod in DANGEROUS_MODULE_NAMES or "wrap_close" in getattr(obj, "__name__", ""):
            return True

    if isinstance(obj, dict):
        for dang in ("eval", "open", "__import__", "exec"):
            if dang in obj and callable(obj[dang]):
                return True
        if depth < 2:
            for k, v in list(obj.items())[:50]:
                if is_dangerous(v, depth + 1, seen):
                    return True

    if isinstance(obj, (list, tuple, set)):
        if depth < 2:
            for item in list(obj)[:50]:
                if is_dangerous(item, depth + 1, seen):
                    return True

    if hasattr(obj, "__globals__") and isinstance(obj.__globals__, dict):
        fn_builtins = obj.__globals__.get("__builtins__")
        if fn_builtins is not None and isinstance(fn_builtins, dict) and "eval" in fn_builtins:
            return True

    return False

stdout_buf = io.StringIO()
stderr_buf = io.StringIO()
executed = False
exc_str = None
capability_recovered = False
byte_code = None

try:
    tree = ast.parse(code)
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        tree.body[-1] = ast.Assign(
            targets=[ast.Name(id='captured_payload_expr', ctx=ast.Store())],
            value=tree.body[-1].value
        )
        ast.fix_missing_locations(tree)
    byte_code = compile_restricted(tree, filename="<sandbox>", mode="exec")
except Exception:
    try:
        byte_code = compile_restricted(code, filename="<sandbox>", mode="exec")
    except Exception as e:
        exc_str = f"{type(e).__name__}: {e}"

if byte_code is not None:
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

    if executed:
        ignored_keys = {
            "_print_", "_getattr_", "_getitem_", "_getiter_",
            "_iter_unpack_sequence_", "_unpack_sequence_", "_write_",
            "__builtins__", "_print"
        }
        for k, v in list(restricted_globals.items()):
            if k in ignored_keys:
                continue
            if is_dangerous(v):
                capability_recovered = True
                break

out = {
    "executed": executed,
    "stdout": stdout_buf.getvalue(),
    "stderr": stderr_buf.getvalue(),
    "exception": exc_str,
    "timed_out": False,
    "capability_recovered": capability_recovered,
}

with open(result_file, "w", encoding="utf-8") as f:
    json.dump(out, f)
"""


def sandbox_exec(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Execute code within an isolated RestrictedPython subprocess.

    Compiles code using RestrictedPython's compile_restricted, executes with
    safe_globals and standard runtime guards inside a dedicated subprocess,
    and returns a structured execution dictionary including capability recovery metrics.

    Args:
        code: Python source code string to compile and execute.
        timeout: Optional execution timeout in seconds. If omitted, uses
            config.timeout_seconds if available, else defaults to 3.0 seconds.
        config: Optional SandboxConfig instance.
        work_dir: Optional working directory for the sandbox execution. If omitted,
            a dedicated disposable temporary directory is created and cleaned up.

    Returns:
        dict[str, Any]: Execution result dictionary with keys:
            - executed (bool): True if code compiled and ran without unhandled errors.
            - stdout (str): Standard output captured during execution.
            - stderr (str): Standard error captured during execution.
            - exception (str | None): Exception message if compilation or execution failed.
            - timed_out (bool): True if execution timed out.
            - capability_recovered (bool): True if dangerous capabilities (e.g. os, eval) were recovered.

    Notes:
        Never raises an uncaught exception back to the caller. A crash or syntax
        error is returned as a recorded result.
    """
    effective_timeout = 3.0
    if timeout is not None:
        effective_timeout = timeout
    elif config is not None:
        effective_timeout = config.timeout_seconds

    def _execute_in_dir(tmp_path: Path) -> dict[str, Any]:
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
                "capability_recovered": False,
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
                "capability_recovered": False,
            }
        except Exception as e:
            return {
                "executed": False,
                "stdout": "",
                "stderr": "",
                "exception": f"{type(e).__name__}: {e}",
                "timed_out": False,
                "capability_recovered": False,
            }

        if result_file.is_file():
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    result_data = json.load(f)
                result_data["capability_recovered"] = bool(result_data.get("capability_recovered", False))
                return result_data
            except Exception as e:
                return {
                    "executed": False,
                    "stdout": proc.stdout or "",
                    "stderr": proc.stderr or "",
                    "exception": f"SerializationError: Failed to read runner output: {e}",
                    "timed_out": False,
                    "capability_recovered": False,
                }
        else:
            return {
                "executed": False,
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "exception": f"ProcessTerminated: Subprocess exited with code {proc.returncode}",
                "timed_out": False,
                "capability_recovered": False,
            }

    if work_dir is not None:
        target_dir = Path(work_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        return _execute_in_dir(target_dir)

    with tempfile.TemporaryDirectory(prefix="sandbox_run_") as tmpdir:
        return _execute_in_dir(Path(tmpdir))



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

    def __init__(
        self,
        sandbox_exec: Callable[..., dict[str, Any]] | None = None,
        oracle: EscapeOracle | Callable[..., bool] | None = None,
        config: SandboxConfig | dict[str, Any] | None = None,
    ) -> None:
        """Initialize the prober with execution engine, oracle, and configuration.

        Args:
            sandbox_exec: Optional execution callable. Defaults to sandbox_exec().
            oracle: Optional EscapeOracle instance or oracle checking callable.
            config: Optional SandboxConfig instance or dictionary.
        """
        # Support positional config passing for backward compatibility
        if isinstance(sandbox_exec, (SandboxConfig, dict)) and config is None and oracle is None:
            config = sandbox_exec
            sandbox_exec = None

        self.config: SandboxConfig = load_config(config)

        self.sandbox_exec: Callable[..., dict[str, Any]] = (
            sandbox_exec if sandbox_exec is not None else globals()["sandbox_exec"]
        )

        if isinstance(oracle, EscapeOracle):
            self.oracle_manager = oracle
            self.oracle_check: Callable[..., bool] = default_oracle_func
        elif callable(oracle):
            self.oracle_check = oracle
            self.oracle_manager = EscapeOracle(self.config)
        else:
            self.oracle_manager = EscapeOracle(self.config)
            self.oracle_check = default_oracle_func

        self.oracle = self.oracle_manager
        self.analyzer = StaticAnalyzer(config=self.config)

    def probe_payload(self, payload: Payload | dict[str, Any]) -> dict[str, Any]:
        """Execute a single payload in a dedicated, isolated subprocess.

        Args:
            payload: Payload specification to execute against RestrictedPython.

        Returns:
            dict[str, Any]: Execution details, static verdict, and oracle verdict.
        """
        results = self.run([payload])
        return results[0]

    def run(
        self, payload_corpus: list[Payload] | list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Execute a corpus of payloads sequentially within isolated subprocesses.

        Args:
            payload_corpus: Optional list of attributed payloads to evaluate.
                If None, defaults to the canonical PAYLOADS corpus.

        Returns:
            list[dict[str, Any]]: Per-payload results containing static verdict,
                execution metrics, oracle ground-truth escape verdicts, and timing.
        """
        from sandbox_escape_finder.oracle import capture_canary_state

        if payload_corpus is None:
            from sandbox_escape_finder.payloads import PAYLOADS

            corpus: list[Payload | dict[str, Any]] = list(PAYLOADS)
        else:
            corpus = list(payload_corpus)

        # Deterministic sampling and ordering respecting config seed
        seed = getattr(self.config, "random_seed", 42)
        rng = random.Random(seed)

        # Support optional shuffling or sampling if requested in config
        if getattr(self.config, "shuffle", False):
            rng.shuffle(corpus)

        report: list[dict[str, Any]] = []

        for idx, item in enumerate(corpus):
            if isinstance(item, dict):
                code = item["code"]
                technique = item["technique"]
                source = item.get("source", "")
                payload_id = item.get("id", f"payload_{idx:02d}")
                description = item.get("description", "")
            else:
                code = item.code
                technique = item.technique
                source = item.source
                payload_id = item.id
                description = item.description

            # Setup throwaway canary for this run
            canary_path = self.oracle_manager.setup_canary()
            pre_state = capture_canary_state(canary_path)

            formatted_code = code.replace("{canary_path}", str(canary_path).replace("\\", "/"))

            start_time = time.perf_counter()
            import inspect

            exec_sig = inspect.signature(self.sandbox_exec)
            exec_kwargs: dict[str, Any] = {
                "timeout": self.config.timeout_seconds,
                "config": self.config,
            }
            if "work_dir" in exec_sig.parameters:
                exec_kwargs["work_dir"] = canary_path.parent

            exec_res = self.sandbox_exec(formatted_code, **exec_kwargs)
            duration = time.perf_counter() - start_time

            post_state = capture_canary_state(canary_path)
            escaped = self.oracle_check(pre_state, exec_res, post_state)
            self.oracle_manager.cleanup()

            static_findings = self.analyzer.scan(code)

            entry: dict[str, Any] = {
                "payload_id": payload_id,
                "technique": technique,
                "source": source,
                "code": code,
                "description": description,
                "static_verdict": static_findings,
                "static_flagged": len(static_findings) > 0,
                "executed": bool(exec_res.get("executed", False)),
                "escaped": bool(escaped),
                "capability_recovered": bool(exec_res.get("capability_recovered", False)),
                "timing": round(duration, 4),
                "stdout": exec_res.get("stdout", ""),
                "stderr": exec_res.get("stderr", ""),
                "exception": exec_res.get("exception"),
                "timed_out": bool(exec_res.get("timed_out", False)),
            }
            report.append(entry)

        return report

