"""SandboxEscapeFinder: Static + dynamic escape analysis for RestrictedPython."""

from sandbox_escape_finder.dynamic_prober import DynamicProber, Payload, sandbox_exec
from sandbox_escape_finder.oracle import EscapeOracle, oracle
from sandbox_escape_finder.payloads import PAYLOADS, get_payload_corpus
from sandbox_escape_finder.static_analyzer import StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
    "DynamicProber",
    "Payload",
    "sandbox_exec",
    "EscapeOracle",
    "oracle",
    "PAYLOADS",
    "get_payload_corpus",
]

__version__ = "0.1.0"


