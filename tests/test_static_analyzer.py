"""Unit tests for AST-based StaticAnalyzer and technique detectors."""

import pytest

from sandbox_escape_finder.config import SandboxConfig, load_config
from sandbox_escape_finder.static_analyzer import (
    Finding,
    StaticAnalyzer,
    detect_globals_access,
    detect_subclasses_traversal,
)


class TestSubclassesTraversalDetector:
    """Tests for the __subclasses__ traversal detector."""

    def test_positive_subclasses_traversal(self) -> None:
        """Clear positive example: chain traversing object hierarchy via __subclasses__()."""
        payload = "().__class__.__bases__[0].__subclasses__()"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["subclasses_traversal"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["technique"] == "subclasses_traversal"
        assert finding["confidence"] == "HIGH"
        assert "subclasses" in finding["reason"].lower()
        # Ensure node_location has line and column (1-indexed line, col >= 0)
        line, col = finding["node_location"]
        assert line == 1
        assert col >= 0

    def test_positive_getattr_subclasses_traversal(self) -> None:
        """Positive example using getattr to dynamically look up __subclasses__."""
        payload = "getattr(object, '__subclasses__')()"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["subclasses_traversal"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        assert findings[0]["technique"] == "subclasses_traversal"
        assert findings[0]["confidence"] == "HIGH"

    def test_negative_subclasses_traversal(self) -> None:
        """Clear negative example: benign class inheritance, isinstance, and 'subclasses' identifier."""
        benign_code = """
class BaseService:
    def __init__(self, name: str):
        self.name = name

    def execute(self) -> bool:
        return True

class PaymentService(BaseService):
    def execute(self) -> bool:
        return False

def verify_service(service) -> bool:
    subclasses = ["payment", "auth", "notification"]
    if service.name in subclasses:
        return isinstance(service, BaseService)
    return False
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["subclasses_traversal"]})
        findings = analyzer.scan(benign_code)
        assert findings == []


class TestGlobalsClosureAccessDetector:
    """Tests for the __globals__ / __closure__ access detector."""

    def test_positive_globals_access(self) -> None:
        """Clear positive example: lambda accessing __globals__ to reach builtins."""
        payload = "(lambda: None).__globals__['__builtins__']"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["globals_access"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["technique"] == "globals_access"
        assert finding["confidence"] == "HIGH"
        assert "__globals__" in finding["reason"]
        line, col = finding["node_location"]
        assert line == 1
        assert col >= 0

    def test_positive_closure_access(self) -> None:
        """Clear positive example: inspecting __closure__ attribute on a function."""
        payload = """
def wrapper():
    secret = 42
    def inner():
        return secret
    return inner

fn = wrapper()
leak = fn.__closure__[0].cell_contents
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["globals_access"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        assert findings[0]["technique"] == "globals_access"
        assert findings[0]["confidence"] == "HIGH"
        assert "__closure__" in findings[0]["reason"]

    def test_negative_globals_and_closure(self) -> None:
        """Clear negative example: benign global variable usage and legitimate nested closures."""
        benign_code = """
GLOBAL_COUNTER = 0

def create_counter(initial: int = 0):
    current = initial
    def increment(step: int = 1) -> int:
        nonlocal current
        current += step
        return current
    return increment

def update_global_counter(amount: int) -> None:
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += amount

counter = create_counter(10)
result = counter(5)
update_global_counter(result)
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["globals_access"]})
        findings = analyzer.scan(benign_code)
        assert findings == []


class TestConfigAndOrchestration:
    """Tests verifying configuration filtering, typed models, and scanner orchestration."""

    def test_config_technique_filtering(self) -> None:
        """Verify that disabling a technique prevents it from reporting findings."""
        code = """
x = ().__class__.__bases__[0].__subclasses__()
y = (lambda: None).__globals__
"""
        # Only subclasses_traversal enabled
        analyzer_subclasses = StaticAnalyzer(config={"enabled_techniques": ["subclasses_traversal"]})
        findings_sub = analyzer_subclasses.scan(code)
        assert len(findings_sub) == 1
        assert findings_sub[0]["technique"] == "subclasses_traversal"

        # Only globals_access enabled
        analyzer_globals = StaticAnalyzer(config={"enabled_techniques": ["globals_access"]})
        findings_glob = analyzer_globals.scan(code)
        assert len(findings_glob) == 1
        assert findings_glob[0]["technique"] == "globals_access"

        # Both enabled by default
        analyzer_default = StaticAnalyzer()
        findings_all = analyzer_default.scan(code)
        assert len(findings_all) == 2
        assert {f["technique"] for f in findings_all} == {"subclasses_traversal", "globals_access"}

        # Empty enabled techniques
        analyzer_none = StaticAnalyzer(config={"enabled_techniques": []})
        assert analyzer_none.scan(code) == []

    def test_typed_config_and_scan_findings(self) -> None:
        """Verify typed SandboxConfig passing and scan_findings returning Finding objects."""
        cfg = load_config({"enabled_techniques": ["subclasses_traversal"]})
        assert isinstance(cfg, SandboxConfig)
        assert cfg.enabled_techniques == ("subclasses_traversal",)

        analyzer = StaticAnalyzer(config=cfg)
        assert analyzer.config.enabled_techniques == ("subclasses_traversal",)

        typed_findings = analyzer.scan_findings("().__class__.__bases__[0].__subclasses__()")
        assert len(typed_findings) == 1
        assert isinstance(typed_findings[0], Finding)
        assert typed_findings[0].technique == "subclasses_traversal"
        assert typed_findings[0].node_location == (1, 0)
        assert typed_findings[0].to_dict()["technique"] == "subclasses_traversal"

    def test_syntax_error_returns_empty_list(self) -> None:
        """Unparseable syntax should be handled gracefully without raising."""
        broken_code = "def invalid_syntax(:"
        analyzer = StaticAnalyzer()
        assert analyzer.scan(broken_code) == []
