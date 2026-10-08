"""AST-based static analyzer for detecting sandbox escape constructs."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Literal

from sandbox_escape_finder.config import CANONICAL_TECHNIQUES, SandboxConfig, load_config


@dataclass(frozen=True)
class Finding:
    """A suspicious AST pattern detected by a static rule.

    Attributes:
        technique: Identifier of the escape technique (e.g., 'subclasses_traversal').
        reason: Plain-text explanation of why this node is suspicious.
        node_location: (line, col) tuple corresponding to the source coordinates.
        confidence: Certainty level ('HIGH', 'MEDIUM', 'LOW').
        node_type: AST node class name (e.g. 'Attribute', 'Call').
    """

    technique: str
    reason: str
    node_location: tuple[int, int]
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
    node_type: str = "Attribute"

    def __init__(
        self,
        technique: str,
        reason: str | None = None,
        node_location: tuple[int, int] | None = None,
        confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH",
        node_type: str = "Attribute",
        description: str | None = None,
        lineno: int | None = None,
        col_offset: int | None = None,
    ) -> None:
        resolved_reason = reason if reason is not None else (description or "")
        resolved_loc = (
            node_location
            if node_location is not None
            else (lineno if lineno is not None else 1, col_offset if col_offset is not None else 0)
        )
        object.__setattr__(self, "technique", technique)
        object.__setattr__(self, "reason", resolved_reason)
        object.__setattr__(self, "node_location", resolved_loc)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "node_type", node_type)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into the standard dictionary format."""
        return {
            "technique": self.technique,
            "node_location": self.node_location,
            "confidence": self.confidence,
            "reason": self.reason,
        }


def detect_subclasses_traversal(tree: ast.AST) -> list[Finding]:
    """Flag attempts to reach object hierarchy via __subclasses__ attribute or call."""
    findings: list[Finding] = []

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)

        if isinstance(node, ast.Attribute) and node.attr == "__subclasses__":
            findings.append(
                Finding(
                    technique="subclasses_traversal",
                    reason="Direct attribute access to '__subclasses__' to traverse runtime class hierarchy.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH",
                    node_type="Attribute",
                )
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "__subclasses__"
        ):
            findings.append(
                Finding(
                    technique="subclasses_traversal",
                    reason="Dynamic getattr() lookup targeting '__subclasses__'.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH",
                    node_type="Call",
                )
            )

    return findings


def detect_globals_access(tree: ast.AST) -> list[Finding]:
    """Flag attempts to escape local function scope via __globals__ or __closure__."""
    findings: list[Finding] = []
    target_attrs = {"__globals__", "__closure__", "func_globals", "func_closure"}

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)

        if isinstance(node, ast.Attribute) and node.attr in target_attrs:
            findings.append(
                Finding(
                    technique="globals_access",
                    reason=f"Direct access to '{node.attr}' to inspect module globals or closure cells.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH",
                    node_type="Attribute",
                )
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in target_attrs
        ):
            findings.append(
                Finding(
                    technique="globals_access",
                    reason=f"Dynamic getattr() lookup targeting '{node.args[1].value}'.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH",
                    node_type="Call",
                )
            )

    return findings


DETECTOR_REGISTRY: dict[str, Callable[[ast.AST], list[Finding]]] = {
    "subclasses_traversal": detect_subclasses_traversal,
    "globals_access": detect_globals_access,
}


class StaticAnalyzer:
    """Scans Python source trees using AST visitor rules."""

    def __init__(self, config: SandboxConfig | dict[str, Any] | None = None) -> None:
        self.config: SandboxConfig = load_config(config)
        self._enabled_detectors: list[str] = [
            tech for tech in self.config.enabled_techniques if tech in DETECTOR_REGISTRY
        ]

    @property
    def enabled_techniques(self) -> list[str]:
        return list(self._enabled_detectors)

    def scan_findings(self, source_code: str) -> list[Finding]:
        """Scan source code and return typed Finding objects."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        for tech in self._enabled_detectors:
            detector = DETECTOR_REGISTRY.get(tech)
            if detector:
                findings.extend(detector(tree))

        findings.sort(key=lambda f: f.node_location)
        return findings

    def scan(self, source_code: str) -> list[dict[str, Any]]:
        """Scan source code and return a list of finding dictionaries."""
        return [f.to_dict() for f in self.scan_findings(source_code)]
