# SandboxEscapeFinder

`SandboxEscapeFinder` is a research toolbox designed to empirically evaluate the defensive boundary of the [RestrictedPython](https://pypi.org/project/RestrictedPython/) sandbox through complementary static and dynamic analysis:

1. **`StaticAnalyzer`**: Inspects Python source code using Abstract Syntax Trees (`ast`) to flag patterns characteristic of known sandbox escape techniques (e.g., introspection, subclass traversal, frame navigation) without running code.
2. **`DynamicProber`**: Executes a corpus of attributed escape payloads against an actual, unmodified `RestrictedPython` environment inside isolated subprocesses, using an automated oracle to verify whether an escape actually succeeds.

The central research output is an empirical comparison (false positives and false negatives) evaluating what static syntax analysis can flag versus what actually breaks out of `RestrictedPython` at runtime.

---

## Safety Constraints & Defensive Scope

This repository is dedicated strictly to **defensive security research**:
- **Strict Isolation**: Dynamic payload execution occurs exclusively in isolated subprocesses with mandatory execution timeouts and disposable directories.
- **Throwaway Canary Targets**: Any escape verification checks a throwaway canary file or token created inside a temporary directory that is cleaned up after execution.
- **Local Sandbox Only**: Payloads run only against local `RestrictedPython` instances. Never against live services, production environments, host file systems, or network endpoints.

---

## Project Structure

```text
SandboxEscapeFinder/
├── src/sandbox_escape_finder/
│   ├── __init__.py          # Package exports: StaticAnalyzer, DynamicProber
│   ├── static_analyzer.py   # AST-based static analysis engine & finding schema
│   ├── dynamic_prober.py    # Subprocess execution harness & reporting schema
│   ├── config.py            # Configuration dataclasses & safety settings
│   └── oracle.py            # Canary lifecycle & escape verification oracle
├── tests/
│   ├── __init__.py
│   └── test_skeleton.py     # Initial package import and structure verification
├── examples/
│   └── quickstart.py        # Example usage walkthrough stub
├── Context Of Task.md       # Research specification & background document
├── README.md                # Project documentation and setup guide
└── pyproject.toml           # Package specification & pinned dependencies
```

---

## Installation

This package requires **Python 3.11+**.

Install in editable mode:
```bash
pip install -e .
```

To install with development dependencies (e.g., `pytest`):
```bash
pip install -e ".[dev]"
```

---

## Pinned Dependencies

| Dependency | Pinned Version | Rationale |
|------------|----------------|-----------|
| `RestrictedPython` | `8.5` | The target sandbox library under evaluation. Version `8.5` is the latest stable release supporting Python 3.11–3.13. |
| `pytest` | `9.1.1` | The test runner for unit tests, oracle validation, and corpus integration tests. Pinned to the latest stable release. |

---

## Module Overview

- **`config.py`**: Minimal configuration schema (`SandboxConfig`) defining execution limits (`timeout_seconds`), disposable canary parameters (`canary_filename`, `canary_secret`), and reproducibility seeds (`random_seed`).
- **`oracle.py`**: Deterministic verification oracle (`EscapeOracle`) that provisions temporary canaries and checks whether an executed payload bypassed sandbox restrictions to access or alter them.
- **`static_analyzer.py`**: Pure AST visitor engine (`StaticAnalyzer`) that parses source code and generates inspectable `Finding` entries indicating technique, AST node type, location, and confidence level.
- **`dynamic_prober.py`**: Isolated execution runner (`DynamicProber`) that launches payloads in standalone subprocesses, tracks execution metrics (`ExecutionResult`), and pairs them with oracle verdicts (`ProbeReportEntry`).
