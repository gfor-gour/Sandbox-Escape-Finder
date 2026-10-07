"""Smoke test ensuring modules and classes can be cleanly imported."""

import pytest

import sandbox_escape_finder
from sandbox_escape_finder import DynamicProber, StaticAnalyzer
from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import Payload
from sandbox_escape_finder.oracle import EscapeOracle
from sandbox_escape_finder.static_analyzer import Finding


def test_package_exports() -> None:
    """Verify that public API classes are exported at the root package level."""
    assert hasattr(sandbox_escape_finder, "StaticAnalyzer")
    assert hasattr(sandbox_escape_finder, "DynamicProber")
    assert StaticAnalyzer is not None
    assert DynamicProber is not None


def test_data_model_instantiation() -> None:
    """Verify that configuration and core dataclasses can be instantiated."""
    cfg = SandboxConfig(timeout_seconds=5.0)
    assert cfg.timeout_seconds == 5.0

    finding = Finding(
        technique="subclass_traversal",
        description="Testing pattern",
        lineno=1,
        col_offset=0,
        node_type="Attribute",
        confidence="HIGH",
    )
    assert finding.technique == "subclass_traversal"

    payload = Payload(
        id="test_01",
        technique="builtins_recovery",
        source="jailctf",
        code="[].__class__",
    )
    assert payload.id == "test_01"
