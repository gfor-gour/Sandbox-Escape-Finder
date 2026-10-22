"""AST-based static analyzer for detecting sandbox escape constructs."""

from __future__ import annotations

import ast
import string
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


def detect_builtins_restoration(tree: ast.AST) -> list[Finding]:
    """Flag attempts to recover stripped built-ins via a '__builtins__' lookup.

    Matches (only in read/Load position, so *setting* '__builtins__' to lock
    things down is not flagged):
      - obj.__builtins__                       (Attribute)
      - <anything>['__builtins__']             (Subscript with constant key)
      - <anything>.get('__builtins__')         (Call with constant first arg)
      - getattr(x, '__builtins__')             (Call)
      - bare name __builtins__                 (Name)
    """
    findings: list[Finding] = []
    globals_attrs = {"__globals__", "func_globals"}

    def is_builtins_const(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value == "__builtins__"

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        loc = (lineno, col_offset)

        if isinstance(node, ast.Attribute) and node.attr == "__builtins__":
            findings.append(
                Finding(
                    technique="builtins_restoration",
                    reason="Direct attribute access to '__builtins__' to recover the built-ins namespace.",
                    node_location=loc,
                    confidence="HIGH",
                    node_type="Attribute",
                )
            )
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and is_builtins_const(node.slice)
        ):
            via_globals = isinstance(node.value, ast.Attribute) and node.value.attr in globals_attrs
            findings.append(
                Finding(
                    technique="builtins_restoration",
                    reason=(
                        "Subscript read of '__builtins__' on a function's globals."
                        if via_globals
                        else "Subscript read of key '__builtins__' from a mapping."
                    ),
                    node_location=loc,
                    confidence="HIGH" if via_globals else "MEDIUM",
                    node_type="Subscript",
                )
            )
        elif (
            isinstance(node, ast.Call)
            and node.args
            and (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and len(node.args) >= 2
                    and is_builtins_const(node.args[1])
                )
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and is_builtins_const(node.args[0])
                )
            )
        ):
            findings.append(
                Finding(
                    technique="builtins_restoration",
                    reason="getattr()/get() lookup targeting '__builtins__'.",
                    node_location=loc,
                    confidence="HIGH",
                    node_type="Call",
                )
            )
        elif isinstance(node, ast.Name) and node.id == "__builtins__" and isinstance(node.ctx, ast.Load):
            findings.append(
                Finding(
                    technique="builtins_restoration",
                    reason="Read of the bare name '__builtins__'.",
                    node_location=loc,
                    confidence="MEDIUM",
                    node_type="Name",
                )
            )

    return findings


_FRAME_HIGH_ATTRS = {"gi_frame", "cr_frame", "ag_frame", "tb_frame", "_getframe", "_current_frames"}
_FRAME_MEDIUM_ATTRS = {"f_back", "f_globals", "f_locals", "f_builtins", "currentframe"}


def detect_frame_introspection(tree: ast.AST) -> list[Finding]:
    """Flag code that obtains or walks frame objects to climb the call stack.

    Attributes that hand out a frame (gi_frame, cr_frame, ag_frame, tb_frame,
    sys._getframe) are HIGH. Attributes that only make sense on a frame
    (f_back, f_globals, f_locals, f_builtins, inspect.currentframe) are MEDIUM
    because an unrelated user class could reuse those names.
    """
    findings: list[Finding] = []
    all_attrs = _FRAME_HIGH_ATTRS | _FRAME_MEDIUM_ATTRS

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)

        if isinstance(node, ast.Attribute) and node.attr in all_attrs:
            findings.append(
                Finding(
                    technique="frame_introspection",
                    reason=f"Access to frame-related attribute '{node.attr}' to reach the call stack.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH" if node.attr in _FRAME_HIGH_ATTRS else "MEDIUM",
                    node_type="Attribute",
                )
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in all_attrs
        ):
            findings.append(
                Finding(
                    technique="frame_introspection",
                    reason=f"Dynamic getattr() lookup targeting frame attribute '{node.args[1].value}'.",
                    node_location=(lineno, col_offset),
                    confidence="HIGH" if node.args[1].value in _FRAME_HIGH_ATTRS else "MEDIUM",
                    node_type="Call",
                )
            )
        elif isinstance(node, ast.Name) and node.id in {"_getframe", "currentframe"} and isinstance(
            node.ctx, ast.Load
        ):
            # e.g. `from sys import _getframe` followed by a bare call
            findings.append(
                Finding(
                    technique="frame_introspection",
                    reason=f"Use of frame accessor '{node.id}'.",
                    node_location=(lineno, col_offset),
                    confidence="MEDIUM",
                    node_type="Name",
                )
            )

    return findings


def _format_field_dunder_attrs(template: str) -> list[str]:
    """Return dunder attribute names that a str.format template would resolve.

    Uses string.Formatter().parse(), which implements the same grammar as
    str.format: '{{' is a literal brace (never a field), and a field's
    format_spec may itself contain nested fields.
    """
    found: list[str] = []
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return found  # malformed template would raise at runtime anyway

    for _literal, field_name, format_spec, _conversion in parsed:
        if field_name:
            # field_name looks like: arg_name(.attr | [index])*
            i = 0
            while i < len(field_name):
                ch = field_name[i]
                if ch == "[":
                    i = field_name.find("]", i)
                    if i == -1:
                        break
                    i += 1
                elif ch == ".":
                    j = i + 1
                    while j < len(field_name) and field_name[j] not in ".[":
                        j += 1
                    attr = field_name[i + 1 : j]
                    if attr.startswith("__") and attr.endswith("__"):
                        found.append(attr)
                    i = j
                else:
                    i += 1
        if format_spec:
            found.extend(_format_field_dunder_attrs(format_spec))
    return found


def detect_format_string_attribute_access(tree: ast.AST) -> list[Finding]:
    """Flag str.format templates that traverse dunder attributes inside the string.

    Unlike detectors 1-4 this does NOT look for ast.Attribute: in
    "{0.__class__}".format(x) the attribute chain exists only inside a
    string constant. We instead find .format/.format_map/.vformat calls whose
    template is a literal string and parse that string with the format grammar.

    f-strings need no special handling: their {expr} parts are real AST nodes
    (JoinedStr > FormattedValue > Attribute), so detectors 1-4 already see them.
    """
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in {"format", "format_map", "vformat"}:
            continue

        receiver = node.func.value
        template: str | None = None
        if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str):
            template = receiver.value  # "...".format(...)
        elif node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            template = node.args[0].value  # str.format("...", x) / Formatter().format("...", x)

        if template is None:
            continue  # non-literal template: not statically resolvable

        attrs = _format_field_dunder_attrs(template)
        if attrs:
            findings.append(
                Finding(
                    technique="format_string_attribute_access",
                    reason=f"Format string traverses dunder attribute(s) {sorted(set(attrs))} inside the template.",
                    node_location=(node.lineno, node.col_offset),
                    confidence="HIGH",
                    node_type="Call",
                )
            )

    return findings


DETECTOR_REGISTRY: dict[str, Callable[[ast.AST], list[Finding]]] = {
    "subclasses_traversal": detect_subclasses_traversal,
    "globals_access": detect_globals_access,
    "builtins_restoration": detect_builtins_restoration,
    "frame_introspection": detect_frame_introspection,
    "format_string_attribute_access": detect_format_string_attribute_access,
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
