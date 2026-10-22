"""Run the full payload corpus and print the static-vs-dynamic comparison.

Static scanning and dynamic probing are done independently here and only
combined by sandbox_escape_finder.reporting. Payloads execute in isolated
subprocesses against a real RestrictedPython instance.

Usage:  python examples/run_comparison.py
"""

from __future__ import annotations

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import DynamicProber
from sandbox_escape_finder.payloads import PAYLOADS
from sandbox_escape_finder.reporting import (
    build_comparison_table,
    to_markdown_summary,
    to_markdown_table,
)
from sandbox_escape_finder.static_analyzer import StaticAnalyzer


def main() -> None:
    config = SandboxConfig()
    analyzer = StaticAnalyzer(config=config)
    findings_by_payload = {p["id"]: analyzer.scan(p["code"]) for p in PAYLOADS}

    prober_report = DynamicProber(config=config).run(PAYLOADS)
    table = build_comparison_table(findings_by_payload, prober_report)

    print(to_markdown_table(table))
    print()
    print(to_markdown_summary(table))


if __name__ == "__main__":
    main()
