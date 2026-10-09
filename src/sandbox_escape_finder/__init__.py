"""SandboxEscapeFinder: Static + dynamic escape analysis for RestrictedPython."""

from sandbox_escape_finder.dynamic_prober import DynamicProber, sandbox_exec
from sandbox_escape_finder.oracle import EscapeOracle, oracle
from sandbox_escape_finder.static_analyzer import StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
    "DynamicProber",
    "sandbox_exec",
    "EscapeOracle",
    "oracle",
]

__version__ = "0.1.0"

