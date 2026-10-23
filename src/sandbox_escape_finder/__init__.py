from sandbox_escape_finder.config import CANONICAL_TECHNIQUES, SandboxConfig, load_config
from sandbox_escape_finder.dynamic_prober import DynamicProber, Payload, sandbox_exec
from sandbox_escape_finder.oracle import CanaryState, EscapeOracle, OracleVerdict, oracle
from sandbox_escape_finder.payloads import PAYLOADS, get_payload_corpus
from sandbox_escape_finder.reporting import (
    build_comparison_table,
    classify_row,
    classify_table,
    to_markdown_summary,
    to_markdown_table,
)
from sandbox_escape_finder.static_analyzer import Finding, StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
    "Finding",
    "DynamicProber",
    "Payload",
    "sandbox_exec",
    "EscapeOracle",
    "CanaryState",
    "OracleVerdict",
    "oracle",
    "SandboxConfig",
    "load_config",
    "CANONICAL_TECHNIQUES",
    "PAYLOADS",
    "get_payload_corpus",
    "build_comparison_table",
    "classify_row",
    "classify_table",
    "to_markdown_table",
    "to_markdown_summary",
]

__version__ = "0.1.0"



