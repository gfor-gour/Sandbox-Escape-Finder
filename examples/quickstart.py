"""Quickstart demonstration for SandboxEscapeFinder."""

from sandbox_escape_finder import DynamicProber, StaticAnalyzer
from sandbox_escape_finder.config import SandboxConfig


def main() -> None:
    print("SandboxEscapeFinder Quickstart")
    print("------------------------------")
    config = SandboxConfig()
    print(f"Loaded default config with timeout: {config.timeout_seconds}s")
    print(f"Enabled techniques: {config.enabled_techniques}")

    analyzer = StaticAnalyzer()
    sample_code = """
# Sample untrusted snippet attempting class traversal
x = ().__class__.__bases__[0].__subclasses__()
y = (lambda: None).__globals__['__builtins__']
"""
    findings = analyzer.scan(sample_code)
    print(f"\nStatic scan found {len(findings)} finding(s):")
    for f in findings:
        line, col = f["node_location"]
        print(f"  - [{f['confidence']}] {f['technique']} at line {line}, col {col}:")
        print(f"    {f['reason']}")


if __name__ == "__main__":
    main()
