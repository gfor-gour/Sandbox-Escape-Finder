"""Unit tests for EscapeOracle, canary state tracking, and escape verification."""

from __future__ import annotations

import io
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable

import pytest

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.oracle import (
    CanaryState,
    EscapeOracle,
    capture_canary_state,
    oracle,
)


@pytest.fixture
def broken_toy_sandbox() -> Callable[[str], dict[str, Any]]:
    """Intentionally broken toy sandbox fixture.

    Deliberately runs code completely unrestricted via Python's built-in exec,
    simulating an unhardened or bypassed sandbox environment for oracle validation.
    """

    def _toy_exec(code: str) -> dict[str, Any]:
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        executed = False
        exc_str = None

        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            try:
                # Deliberately unrestricted execution
                exec(code, {"__builtins__": __builtins__})
                executed = True
            except BaseException as e:
                executed = False
                exc_str = f"{type(e).__name__}: {e}"

        return {
            "executed": executed,
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
            "exception": exc_str,
            "timed_out": False,
        }

    return _toy_exec


class TestEscapeOracle:
    """Tests for the canary lifecycle, state diffing, and escape detection."""

    def test_toy_sandbox_catches_obvious_escape(
        self,
        broken_toy_sandbox: Callable[[str], dict[str, Any]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirm that the oracle detects when an unrestricted sandbox modifies the canary."""
        oracle_inst = EscapeOracle()
        canary_path = oracle_inst.setup_canary()

        try:
            assert canary_path.is_file()
            pre_state = capture_canary_state(canary_path)

            # Malicious payload targeting the canary file
            escape_payload = f"""
with open(r'{canary_path}', 'w') as f:
    f.write('COMPROMISED_CANARY_CONTENT')
"""
            exec_result = broken_toy_sandbox(escape_payload)
            assert exec_result["executed"] is True

            post_state = capture_canary_state(canary_path)

            # Direct oracle function evaluation
            escaped = oracle(pre_state, exec_result, post_state)
            assert escaped is True

            # EscapeOracle evaluate method
            verdict = oracle_inst.evaluate(exec_result)
            assert verdict.escaped is True
            assert "compromised" in verdict.reason.lower()

            # Inspectability verification: check printed output
            captured = capsys.readouterr()
            assert "[ORACLE ESCAPE DETECTED]" in captured.out
            assert "modified" in captured.out.lower()
            assert "COMPROMISED_CANARY_CONTENT" in captured.out

        finally:
            oracle_inst.cleanup()

    def test_toy_sandbox_reports_no_escape_for_benign_payload(
        self,
        broken_toy_sandbox: Callable[[str], dict[str, Any]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirm that a benign payload that touches nothing returns escaped=False."""
        oracle_inst = EscapeOracle()
        canary_path = oracle_inst.setup_canary()

        try:
            pre_state = capture_canary_state(canary_path)

            benign_payload = """
def compute_sum(n: int) -> int:
    return sum(range(n))

result = compute_sum(100)
"""
            exec_result = broken_toy_sandbox(benign_payload)
            assert exec_result["executed"] is True

            post_state = capture_canary_state(canary_path)

            escaped = oracle(pre_state, exec_result, post_state)
            assert escaped is False

            verdict = oracle_inst.evaluate(exec_result)
            assert verdict.escaped is False
            assert "intact" in verdict.reason.lower()

            # Inspectability verification: nothing printed when no escape
            captured = capsys.readouterr()
            assert "[ORACLE ESCAPE DETECTED]" not in captured.out

        finally:
            oracle_inst.cleanup()

    def test_oracle_catches_canary_deletion(
        self,
        broken_toy_sandbox: Callable[[str], dict[str, Any]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirm oracle detects if canary file is deleted by payload."""
        with EscapeOracle() as oracle_inst:
            canary_path = oracle_inst.canary_path
            assert canary_path is not None and canary_path.is_file()

            delete_payload = f"""
import os
os.remove(r'{canary_path}')
"""
            exec_result = broken_toy_sandbox(delete_payload)
            verdict = oracle_inst.evaluate(exec_result)

            assert verdict.escaped is True
            captured = capsys.readouterr()
            assert "[ORACLE ESCAPE DETECTED]" in captured.out
            assert "deleted" in captured.out.lower()

    def test_oracle_catches_unexpected_canary_creation(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirm oracle detects when a non-existent canary is created."""
        target_path = tmp_path / "new_canary.txt"
        pre_state = capture_canary_state(target_path)
        assert pre_state.exists is False

        # Simulate creation
        target_path.write_text("CREATED_BY_PAYLOAD", encoding="utf-8")
        post_state = capture_canary_state(target_path)

        escaped = oracle(pre_state, {"executed": True, "stdout": ""}, post_state)
        assert escaped is True

        captured = capsys.readouterr()
        assert "[ORACLE ESCAPE DETECTED]" in captured.out
        assert "created" in captured.out.lower()

    def test_oracle_catches_secret_exfiltration_to_stdout(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirm oracle detects when canary secret token is leaked via stdout."""
        secret = "SUPER_SECRET_CANARY_TOKEN_98765"
        state = CanaryState(
            path=Path("/tmp/canary.txt"),
            exists=True,
            content=secret,
            mtime=100.0,
            size=len(secret),
        )

        exec_result = {
            "executed": True,
            "stdout": f"Leaked content is: {secret} in output\n",
            "stderr": "",
            "exception": None,
            "timed_out": False,
        }

        # Content on disk didn't change, but was read and exfiltrated
        escaped = oracle(state, exec_result, state)
        assert escaped is True

        captured = capsys.readouterr()
        assert "[ORACLE ESCAPE DETECTED]" in captured.out
        assert "exfiltrated" in captured.out.lower()

    def test_canary_lifecycle_and_cleanup(self) -> None:
        """Verify setup_canary creates a disposable file and cleanup removes it."""
        oracle_inst = EscapeOracle()
        canary_path = oracle_inst.setup_canary()

        assert canary_path.is_file()
        assert oracle_inst.work_dir is not None
        assert oracle_inst.work_dir.is_dir()

        oracle_inst.cleanup()
        assert not canary_path.exists()
        assert not oracle_inst.work_dir.exists()

    def test_context_manager_support(self) -> None:
        """Verify EscapeOracle works as a context manager with automatic teardown."""
        temp_dir_to_check = None
        with EscapeOracle() as oracle_inst:
            assert oracle_inst.canary_path is not None
            assert oracle_inst.canary_path.is_file()
            temp_dir_to_check = oracle_inst.work_dir

        assert temp_dir_to_check is not None
        assert not temp_dir_to_check.exists()

    def test_builtins_direct_canary_write_in_toy_sandbox(
        self,
        broken_toy_sandbox: Callable[[str], dict[str, Any]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Verify builtins_direct_canary_write targets the actual canary path and registers escape."""
        from sandbox_escape_finder.payloads import PAYLOADS

        payload = next(p for p in PAYLOADS if p["id"] == "builtins_direct_canary_write")
        with EscapeOracle() as oracle_inst:
            canary_path = oracle_inst.canary_path
            assert canary_path is not None
            code = payload["code"].replace("{canary_path}", str(canary_path).replace("\\", "/"))

            exec_result = broken_toy_sandbox(code)
            assert exec_result["executed"] is True

            verdict = oracle_inst.evaluate(exec_result)
            assert verdict.escaped is True
            assert canary_path.read_text(encoding="utf-8") == "PWNED"
