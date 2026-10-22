"""Unit tests for sandbox_exec subprocess execution, DynamicProber, and payload corpus."""

from __future__ import annotations

from typing import Any

import pytest

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import DynamicProber, Payload, sandbox_exec
from sandbox_escape_finder.payloads import PAYLOADS, get_payload_corpus


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
        assert result["capability_recovered"] is False

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


class TestDynamicProberCorpus:
    """Tests running the payload corpus through DynamicProber."""

    def test_payload_corpus_minimum_size_and_schema(self) -> None:
        """Verify the corpus contains at least 10 payloads with required schema."""
        corpus = get_payload_corpus()
        assert len(corpus) >= 10
        for p in corpus:
            assert isinstance(p["code"], str) and len(p["code"]) > 0
            assert isinstance(p["technique"], str) and len(p["technique"]) > 0
            assert isinstance(p["source"], str) and len(p["source"]) > 0

    def test_real_corpus_run_shape_and_keys(self) -> None:
        """Run the real corpus against real RestrictedPython and assert report shape."""
        prober = DynamicProber(config=SandboxConfig(timeout_seconds=2.0))
        report = prober.run(PAYLOADS)

        assert len(report) == len(PAYLOADS)
        assert len(report) >= 10

        required_keys = {
            "payload_id",
            "technique",
            "source",
            "code",
            "static_verdict",
            "static_flagged",
            "executed",
            "escaped",
            "capability_recovered",
            "timing",
            "stdout",
            "stderr",
            "exception",
            "timed_out",
        }

        for row in report:
            assert required_keys.issubset(row.keys())
            assert isinstance(row["payload_id"], str)
            assert isinstance(row["technique"], str)
            assert isinstance(row["source"], str)
            assert isinstance(row["code"], str)
            assert isinstance(row["static_verdict"], list)
            assert isinstance(row["static_flagged"], bool)
            assert isinstance(row["executed"], bool)
            assert isinstance(row["escaped"], bool)
            assert isinstance(row["capability_recovered"], bool)
            assert isinstance(row["timing"], float)
            assert row["timing"] >= 0.0

            # Under real RestrictedPython, none of the corpus payloads break out
            assert row["escaped"] is False
            assert row["capability_recovered"] is False

    def test_dependency_injection_custom_exec_and_oracle(self) -> None:
        """Verify custom sandbox_exec and oracle functions can be injected into DynamicProber."""
        custom_exec_called = False
        custom_oracle_called = False

        def mock_exec(code: str, timeout: float = 3.0, config: Any = None) -> dict[str, Any]:
            nonlocal custom_exec_called
            custom_exec_called = True
            return {
                "executed": True,
                "stdout": "mocked",
                "stderr": "",
                "exception": None,
                "timed_out": False,
                "capability_recovered": True,
            }

        def mock_oracle(pre: Any, res: Any, post: Any) -> bool:
            nonlocal custom_oracle_called
            custom_oracle_called = True
            return True

        custom_prober = DynamicProber(
            sandbox_exec=mock_exec,
            oracle=mock_oracle,
            config={"seed": 100},
        )

        test_payload = [
            {"id": "p0", "code": "pass", "technique": "test_tech", "source": "test_source"}
        ]
        results = custom_prober.run(test_payload)

        assert custom_exec_called is True
        assert custom_oracle_called is True
        assert len(results) == 1
        assert results[0]["executed"] is True
        assert results[0]["escaped"] is True
        assert results[0]["capability_recovered"] is True

    def test_probe_single_payload(self) -> None:
        """Verify probe_payload executes a single payload and returns expected dict."""
        prober = DynamicProber()
        single_result = prober.probe_payload(PAYLOADS[0])

        assert isinstance(single_result, dict)
        assert single_result["payload_id"] == PAYLOADS[0]["id"]
        assert single_result["technique"] == PAYLOADS[0]["technique"]
        assert "escaped" in single_result
        assert "executed" in single_result
        assert "static_verdict" in single_result
