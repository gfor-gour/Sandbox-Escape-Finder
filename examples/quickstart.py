"""Quickstart demonstration for SandboxEscapeFinder.

Runs the complete end-to-end pipeline:
1. Static analysis of untrusted Python code using AST traversal rules.
2. Isolated dynamic execution in subprocesses with canary oracle verification.
3. Cross-referenced static vs. dynamic comparison table generation and confusion matrix.
"""

from __future__ import annotations

from sandbox_escape_finder import (
    DynamicProber,
    SandboxConfig,
    StaticAnalyzer,
    build_comparison_table,
    oracle,
    sandbox_exec,
    to_markdown_summary,
    to_markdown_table,
)
from sandbox_escape_finder.payloads import PAYLOADS


def main() -> None:
    print("=" * 60)
    print("SandboxEscapeFinder: End-to-End Pipeline Demonstration")
    print("=" * 60)

    # 1. Configuration setup (timeouts, reproducible random seed)
    config = SandboxConfig(timeout_seconds=2.0, random_seed=42)
    print(f"\n[1] Configuration:")
    print(f"    - Execution Timeout: {config.timeout_seconds}s")
    print(f"    - Random Seed: {config.random_seed} (reproducible ordering)")
    print(f"    - Enabled Technique Detectors: {len(config.enabled_techniques)}")
    for tech in config.enabled_techniques:
        print(f"      * {tech}")

    # 2. Standalone Static Analysis Demo
    print(f"\n[2] Static Analysis Demo (AST Pattern Inspection):")
    analyzer = StaticAnalyzer(config=config)
    sample_code = (
        "# Sample untrusted snippet attempting class traversal and globals access\n"
        "x = ().__class__.__bases__[0].__subclasses__()\n"
        "y = (lambda: None).__globals__['__builtins__']\n"
    )
    findings = analyzer.scan(sample_code)
    print(f"    Scanned snippet produced {len(findings)} finding(s):")
    for f in findings:
        line, col = f["node_location"]
        print(f"    - [{f['confidence']}] {f['technique']} at line {line}, col {col}: {f['reason']}")

    # 3. Dynamic Probing across Payload Corpus
    # Using the required Task 6 public API: DynamicProber(sandbox_exec, oracle, config)
    print(f"\n[3] Dynamic Probing (Subprocess Isolation + Canary Oracle):")
    print(f"    Executing {len(PAYLOADS)} payloads against local RestrictedPython...")
    prober = DynamicProber(sandbox_exec, oracle, config)
    findings_by_payload = {p["id"]: analyzer.scan(p["code"]) for p in PAYLOADS}
    prober_report = prober.run(PAYLOADS)
    print(f"    Execution complete: {len(prober_report)} payload runs evaluated.")

    # 4. Cross-Reference & Comparison Table
    print(f"\n[4] Cross-Referencing Static Flagged vs. Dynamically Escaped:")
    table = build_comparison_table(findings_by_payload, prober_report)

    print("\n--- Comparison Table ---")
    print(to_markdown_table(table))

    print("\n--- Confusion Matrix & Technique Breakdown ---")
    print(to_markdown_summary(table))
    print("\n" + "=" * 60)
    print("Pipeline run completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()

