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


class TestBuiltinsRestorationDetector:
    """Tests for the __builtins__ restoration detector."""

    def test_positive_globals_builtins_subscript(self) -> None:
        payload = "(lambda: None).__globals__['__builtins__']['eval']"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["builtins_restoration"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        assert findings[0]["technique"] == "builtins_restoration"
        assert findings[0]["confidence"] == "HIGH"
        assert "__builtins__" in findings[0]["reason"]
        assert findings[0]["node_location"] == (1, 0)

    def test_positive_getattr_and_get_variants(self) -> None:
        payload = "a = getattr(fn, '__builtins__')\nb = env.get('__builtins__')\n"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["builtins_restoration"]})
        findings = analyzer.scan(payload)
        assert [f["node_location"][0] for f in findings] == [1, 2]

    def test_negative_setting_and_defining_builtins(self) -> None:
        """Tricky: the key '__builtins__' appears, but only to *lock down* an exec env."""
        benign_code = """
env = {"__builtins__": {}}
env["__builtins__"] = {"len": len}
keys = ["__builtins__", "__name__"]
msg = "do not touch __builtins__ here"
safe = env.get("user_value")
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["builtins_restoration"]})
        assert analyzer.scan(benign_code) == []


class TestFrameIntrospectionDetector:
    """Tests for the generator / frame introspection detector."""

    def test_positive_gi_frame_f_back_chain(self) -> None:
        payload = "g = (x for x in [1])\nf = g.gi_frame.f_back.f_globals\n"
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["frame_introspection"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 3
        assert {f["technique"] for f in findings} == {"frame_introspection"}
        by_reason = {f["reason"]: f["confidence"] for f in findings}
        assert by_reason["Access to frame-related attribute 'gi_frame' to reach the call stack."] == "HIGH"
        assert by_reason["Access to frame-related attribute 'f_back' to reach the call stack."] == "MEDIUM"
        assert all(f["node_location"][0] == 2 for f in findings)

    def test_positive_sys_getframe(self) -> None:
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["frame_introspection"]})
        findings = analyzer.scan("import sys\nsys._getframe(1)\n")
        assert len(findings) == 1
        assert findings[0]["confidence"] == "HIGH"

    def test_negative_ordinary_generators(self) -> None:
        """Tricky: heavy generator use, a variable called 'frame', and frame words in strings."""
        benign_code = """
def numbers(limit):
    for i in range(limit):
        received = yield i
        if received:
            return

gen = numbers(5)
first = next(gen)
gen.send(None)
running = gen.gi_running
frame = {"gi_frame": "just a dict key", "f_back": 1}
label = "call f_back to go up"
result = frame["f_back"] + len(label)
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["frame_introspection"]})
        assert analyzer.scan(benign_code) == []


class TestFormatStringAttributeAccessDetector:
    """Tests for the str.format implicit attribute access detector."""

    def test_positive_format_dunder_chain(self) -> None:
        payload = '"{0.__init__.__globals__}".format(some_func)'
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["format_string_attribute_access"]})
        findings = analyzer.scan(payload)

        assert len(findings) == 1
        assert findings[0]["technique"] == "format_string_attribute_access"
        assert findings[0]["confidence"] == "HIGH"
        assert "__init__" in findings[0]["reason"] and "__globals__" in findings[0]["reason"]
        assert findings[0]["node_location"] == (1, 0)

    def test_positive_nested_spec_and_str_format_form(self) -> None:
        payload = 'str.format("{0:{1.__class__}}", a, b)'
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["format_string_attribute_access"]})
        assert len(analyzer.scan(payload)) == 1

    def test_negative_benign_and_escaped_format(self) -> None:
        """Tricky: attribute/index access in format, plus an escaped-brace dunder that is literal text."""
        benign_code = """
user = get_user()
a = "{0.name} has {1[key]} items".format(user, data)
b = "{{0.__class__}} is literal text".format()
c = "{0!r:>{width}}".format(user, width=10)
d = "{x.__class__}"  # not formatted at all
"""
        analyzer = StaticAnalyzer(config={"enabled_techniques": ["format_string_attribute_access"]})
        assert analyzer.scan(benign_code) == []

    def test_fstring_is_not_this_detectors_job(self) -> None:
        """f-string attribute access is a normal ast.Attribute, caught by detector 2."""
        payload = "f'{fn.__globals__}'"
        fmt = StaticAnalyzer(config={"enabled_techniques": ["format_string_attribute_access"]})
        glob = StaticAnalyzer(config={"enabled_techniques": ["globals_access"]})
        assert fmt.scan(payload) == []
        assert len(glob.scan(payload)) == 1


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
