"""Quickstart demonstration skeleton for SandboxEscapeFinder.

This script illustrates the intended workflow once detectors, payloads,
and probers are implemented.
"""

from sandbox_escape_finder import DynamicProber, StaticAnalyzer
from sandbox_escape_finder.config import SandboxConfig


def main() -> None:
    print("SandboxEscapeFinder Quickstart")
    print("------------------------------")
    config = SandboxConfig()
    print(f"Loaded default config with timeout: {config.timeout_seconds}s")
    print(f"Static analyzer class: {StaticAnalyzer.__name__}")
    print(f"Dynamic prober class: {DynamicProber.__name__}")


if __name__ == "__main__":
    main()
