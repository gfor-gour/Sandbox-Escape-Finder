"""Quickstart demonstration for SandboxEscapeFinder."""

from sandbox_escape_finder import DynamicProber, StaticAnalyzer
from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.payloads import PAYLOADS


def main() -> None:
    print("SandboxEscapeFinder Quickstart")
    print("------------------------------")
    config = SandboxConfig(timeout_seconds=2.0)
    print(f"Loaded default config with timeout: {config.timeout_seconds}s")
    print(f"Enabled techniques: {config.enabled_techniques}")

    analyzer = StaticAnalyzer(config=config)
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

    print("\nRunning DynamicProber against sample payload corpus...")
    prober = DynamicProber(config=config)
    results = prober.run(PAYLOADS[:3])
    print(f"Executed {len(results)} payload(s):")
    for r in results:
        status = "ESCAPED" if r["escaped"] else ("BLOCKED" if not r["executed"] else "CONTAINED")
        print(f"  - [{r['technique']}] {r['payload_id']}: {status} (timing: {r['timing']}s)")


if __name__ == "__main__":
    main()

