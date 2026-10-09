"""Unit tests for sandbox_exec subprocess execution and safety controls."""

from __future__ import annotations

import pytest

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import DynamicProber, sandbox_exec


class TestSandboxExec:
    """Tests for isolated subprocess execution with RestrictedPython."""

    def test_benign_code_executes_successfully(self) -> None:
        """Verify standard benign code compiles, executes, and captures stdout."""
        code = """
a = 10
b = 20
total = a + b
print(f"total: {total}")
"""
        result = sandbox_exec(code)
        assert result["executed"] is True
        assert "total: 30" in result["stdout"]
        assert result["exception"] is None
        assert result["timed_out"] is False

    def test_restricted_syntax_reported_as_result_not_exception(self) -> None:
        """Verify RestrictedPython compiler errors (e.g. leading underscore) are caught."""
        # RestrictedPython rejects attribute names starting with '_'
        code = "x = ().__class__"
        result = sandbox_exec(code)

        assert result["executed"] is False
        assert result["exception"] is not None
        assert "SyntaxError" in result["exception"]
        assert "__class__" in result["exception"]
        assert result["timed_out"] is False

    def test_runtime_exception_reported_as_result_not_crash(self) -> None:
        """Verify runtime exceptions inside the sandbox are returned in result dict."""
        code = "result = 1 / 0"
        result = sandbox_exec(code)

        assert result["executed"] is False
        assert result["exception"] is not None
        assert "ZeroDivisionError" in result["exception"]
        assert result["timed_out"] is False

    def test_timeout_kills_hanging_payload(self) -> None:
        """Verify CPU-bound infinite loops are terminated cleanly via timeout."""
        code = "while True: pass"
        result = sandbox_exec(code, timeout=0.5)

        assert result["executed"] is False
        assert result["timed_out"] is True
        assert result["exception"] is not None
        assert "TimeoutExpired" in result["exception"]

    def test_config_driven_timeout(self) -> None:
        """Verify SandboxConfig timeout setting applies to sandbox_exec."""
        cfg = SandboxConfig(timeout_seconds=0.4)
        code = "while True: pass"
        result = sandbox_exec(code, config=cfg)

        assert result["executed"] is False
        assert result["timed_out"] is True
        assert "0.4" in result["exception"]

    def test_system_exit_handled_gracefully(self) -> None:
        """Verify code attempting to call sys.exit does not crash caller."""
        code = "raise SystemExit('sandbox terminated')"
        result = sandbox_exec(code)

        assert result["executed"] is False
        assert result["exception"] is not None
        assert "SystemExit" in result["exception"]
        assert result["timed_out"] is False
