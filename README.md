# SandboxEscapeFinder

`SandboxEscapeFinder` is a research toolbox designed to empirically evaluate the defensive boundary of the [RestrictedPython](https://pypi.org/project/RestrictedPython/) sandbox through complementary static syntax analysis and isolated dynamic execution.

The project pairs two decoupled systems:
1. **`StaticAnalyzer`**: Inspects Python Abstract Syntax Trees (`ast`) to flag syntactic patterns characteristic of known sandbox escape techniques (subclass traversal, globals extraction, builtins recovery, frame climbing, and format-string introspection) without running code.
2. **`DynamicProber`**: Executes a curated corpus of attributed escape payloads against an actual, unmodified `RestrictedPython` environment inside isolated subprocesses, using an automated canary oracle to verify whether any payload breaks out in practice.

The core research contribution is an empirical cross-reference (confusion matrix of false positives and false negatives) comparing what static syntax rules flag against what actually breaks through `RestrictedPython`'s defensive layers at runtime.

---

## Defensive Scope & Safety Guarantees

This repository is built strictly for **defensive security evaluation**:
- **Process Isolation**: Every dynamic execution runs in an independent child subprocess. A fatal crash, memory corruption, `sys.exit()`, or `os._exit()` in untrusted code terminates only the worker process, leaving the parent prober intact.
- **Throwaway Canary Fixtures**: Payloads are never targeted at host paths or system files. Escape verification checks a disposable canary token placed inside a throwaway temporary directory (`tempfile.mkdtemp`) that is purged after execution.
- **Strict Execution Timeouts**: Subprocesses are bounded by a configurable wall-clock timeout (`timeout_seconds`, default 2.0s). Infinite loops and blocking operations are forcefully killed.
- **Local Targets Only**: Dynamic testing runs only against local, self-contained `RestrictedPython` instances. Never against live services, external hosts, or production environments.

---

## Installation

This package requires **Python 3.11+**.

Clone the repository and install in editable mode:
```bash
git clone https://github.com/gfor-gour/Sandbox-Escape-Finder.git
cd SandboxEscapeFinder
pip install -e .
```

To install development dependencies (e.g., `pytest`):
```bash
pip install -e ".[dev]"
```

### Dependencies
### Pinned Dependencies
- **`RestrictedPython == 8.5`**: Target sandboxing library under evaluation (strictly pinned to version 8.5 to guarantee deterministic behavior against the exact AST rewrites and guards evaluated).
- **`pytest == 9.1.1`**: Automated test runner for static unit tests, oracle validation, and corpus integration passes.

---

## Quickstart & Usage

The entire pipeline—static analysis, isolated dynamic execution, and cross-referenced reporting—runs via `examples/quickstart.py`:

```bash
python examples/quickstart.py
```

### Programmatic Usage

The snippet below demonstrates the required public API (`DynamicProber(sandbox_exec, oracle, config)`) with reproducible seeding:

```python
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

# 1. Initialize configuration with explicit timeout and reproducible seed
config = SandboxConfig(timeout_seconds=2.0, random_seed=42)
analyzer = StaticAnalyzer(config=config)

# 2. DynamicProber using the canonical dependency-injected signature:
#    DynamicProber(sandbox_exec, oracle, config)
#    (Note: sandbox_exec and oracle optionally default to the built-in isolated
#    execution engine and EscapeOracle if omitted, e.g. DynamicProber(config=config))
prober = DynamicProber(sandbox_exec, oracle, config)

# 3. Static AST analysis over code snippets or payload corpus
findings_by_payload = {p["id"]: analyzer.scan(p["code"]) for p in PAYLOADS}

# 4. Dynamic probing in isolated subprocesses against RestrictedPython
prober_report = prober.run(PAYLOADS)

# 5. Cross-reference static findings against dynamic execution outcomes
table = build_comparison_table(findings_by_payload, prober_report)

# 6. Output Markdown results table and confusion matrix
print(to_markdown_table(table))
print()
print(to_markdown_summary(table))
```

---

## Detected Technique Classes

The static analyzer implements pure AST visitor rules for five primary escape classes. Below is what each technique does, how it attempts an escape, and whether `RestrictedPython` stops it:

### 1. Subclasses Traversal (`subclasses_traversal`)
- **Mechanism**: Navigates Python's in-memory class hierarchy starting from basic object instances or literals (e.g. `().__class__.__bases__[0].__subclasses__()` or `(1).__class__.__base__.__subclasses__()`) to discover loaded internal gadgets like `os._wrap_close`, `catch_warnings`, or `subprocess.Popen`.
- **Static Detection**: Flags `ast.Attribute` access to `__subclasses__` and literal calls to `getattr(..., "__subclasses__")`.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  RestrictedPython stops direct subclass traversal at compile time via its AST policy forbidding attribute names with leading underscores (`__class__`, `__bases__`, `__subclasses__`). However, if an attacker attempts dynamic assembly via `getattr(object, '__sub' + 'classes__')()`, the compile-time AST check is blind; here, RestrictedPython still stops it at runtime because `getattr` is stripped from `safe_globals`. If `getattr` were ever provided, the `safer_getattr` runtime guard would intercept accesses to underscore attributes unless explicitly whitelisted.

### 2. Globals Access (`globals_access`)
- **Mechanism**: Inspects function objects, lambdas, or closure cell objects via `__globals__`, `func_globals`, or `__closure__[0].cell_contents.__globals__` to break out of restricted local scopes and access outer module variables or unrestricted builtins dictionaries.
- **Static Detection**: Flags `ast.Attribute` access to `__globals__`, `__closure__`, `func_globals`, or `func_closure`, as well as equivalent `getattr` invocations.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  RestrictedPython stops `__globals__` and `__closure__` at compile-time rewrite because attribute names starting with `_` raise a `SyntaxError` during `compile_restricted`. Legacy aliases like `func_globals` (which don't start with an underscore) compile cleanly, but fail safely at runtime on modern Python 3 with an `AttributeError` because the attribute was deprecated and removed.

### 3. Builtins Restoration (`builtins_restoration`)
- **Mechanism**: Attempts to retrieve dangerous built-in functions (e.g., `open`, `__import__`, `eval`, `exec`) by querying `__builtins__` directly, traversing `__loader__.__class__.__init__.__globals__`, or inspecting object bindings like `chr.__self__`.
- **Static Detection**: Flags `ast.Attribute`, `ast.Subscript` reads of `__builtins__`, `ast.Call` to `getattr(..., "__builtins__")`, or read-context `ast.Name` nodes for `__builtins__`.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  Direct access to `__builtins__` is rejected at compile time by `compile_restricted` because `__builtins__` starts with an underscore. Furthermore, inside `safe_globals`, only harmless builtins (e.g., `len`, `range`, `abs`) are provided, completely omitting dangerous functions like `open` or `__import__`. For gadgets that evade dunder names (e.g. `chr.__self__`), the expression evaluates safely to Python's `builtins` module, but subsequent attempts to pull unwhitelisted attributes off that module are blocked either by runtime guards (`safer_getattr`) or standard `safe_globals` constraints.

### 4. Frame Introspection (`frame_introspection`)
- **Mechanism**: Reaches the call stack using generator frames (`gi_frame`), coroutine frames (`cr_frame`), asynchronous generator frames (`ag_frame`), traceback objects (`tb_frame`), or `sys._getframe()` / `inspect.currentframe()`, then walks upward via `f_back` to grab caller frames and extract unrestricted globals.
- **Static Detection**: Flags frame-yielding attributes (`gi_frame`, `cr_frame`, `tb_frame`, `_getframe`) with HIGH confidence, and frame-navigation attributes (`f_back`, `f_globals`, `f_builtins`) with MEDIUM confidence.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  RestrictedPython explicitly configures compile-time policies that forbid access to frame navigation attributes. While `gi_frame` and `cr_frame` lack leading underscores, RestrictedPython's AST policy specifically designates `f_back`, `f_globals`, `f_locals`, and `f_builtins` as restricted names, raising a `SyntaxError: "f_back" is a restricted name` during compilation. Additionally, `sys` is excluded from `safe_globals`, so direct calls to `_getframe` fail at compile-time (underscore rule) or runtime (`NameError`).

### 5. Format String Attribute Access (`format_string_attribute_access`)
- **Mechanism**: Leverages Python's `str.format()` or `format_map()` template mini-language (e.g. `"{0.__class__.__bases__[0]}".format("")`) to perform attribute traversal inside string constants, bypassing conventional AST `ast.Attribute` checks.
- **Static Detection**: Parses literal format template strings inside `.format()`, `.format_map()`, and `.vformat()` calls using `string.Formatter().parse()` to identify embedded dunder attributes.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  RestrictedPython permits strings containing format templates to compile, as the attribute traversal is hidden inside string literals. However, at runtime, RestrictedPython wraps all attribute resolution through `safer_getattr`. The `safer_getattr` guard explicitly raises a `NotImplementedError: "Using the format*() methods of 'str' is not safe"` whenever `.format()`, `.format_map()`, or `.format_field()` is accessed on a string, completely neutralizing this vector at runtime.

---

## Canary Oracle Design & Subprocess Isolation

Rather than relying on heuristics or exit codes, `SandboxEscapeFinder` uses a deterministic **Canary Oracle** (`EscapeOracle`):

```text
[Disposable Temp Directory]
           │
           ▼
   setup_canary()  ──►  Create canary_token.txt with secret string
           │
           ▼
   pre_state       ──►  Capture snapshot: {exists, content, mtime, size}
           │
           ▼
  Isolated Worker  ──►  Run payload inside isolated subprocess (timeout enforced)
           │
           ▼
   post_state      ──►  Recapture snapshot: {exists, content, mtime, size}
           │
           ▼
 oracle(pre, res, post) ──► Deterministic 5-point integrity check
```

### Deterministic Breach Conditions
The oracle confirms an escape if and only if one of these concrete conditions occurs:
1. **Unexpected Creation**: The canary file did not exist prior to execution but exists afterward.
2. **Unexpected Deletion**: The canary file existed before execution but was unlinked.
3. **Content Modification**: The file content differs from pre-state (`pre.content != post.content`).
4. **Metadata Alteration**: File size or modification timestamp changed unexpectedly.
5. **Secret Exfiltration**: Untrusted code read the canary secret token and leaked it into `stdout`.

### Capability Recovery Analysis
In addition to filesystem canary checks, the worker inspects the sandboxed environment's global namespace after execution. If untrusted code successfully bound dangerous callables (`eval`, `exec`, `open`, `__import__`, `os.system`), dangerous modules (`os`, `sys`, `subprocess`, `shutil`), or live frame objects, `capability_recovered` is flagged as an escape.

---

## Empirical Results (Prompt 7 Full Comparison Table)

The 20 curated payloads (sourced from `moshekaplan/python_sandbox_escapes`, `jailctf/pyjailbreaker`, and standard escape catalogs) were scanned with `StaticAnalyzer` and executed via `DynamicProber` against `RestrictedPython 8.5`.

| payload_id | technique | static_flagged | static_confidence | dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |
|---|---|---|---|---|---|---|---|---|---|
| `subclasses_tuple_base` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1491 | False positive |
| `subclasses_mro_catch_warnings` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1293 | False positive |
| `subclasses_int_hierarchy` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1282 | False positive |
| `globals_lambda_builtins` | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1237 | False positive |
| `globals_closure_leak` | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1310 | False positive |
| `globals_func_globals_alias` | globals_access | True | HIGH | True | False | False | Contained (safe execution) | 0.1212 | False positive |
| `builtins_direct_canary_write` | builtins_restoration | True | MEDIUM | False | False | False | Compile-time (underscore rule) | 0.1409 | False positive |
| `builtins_loader_recovery` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1497 | False positive |
| `frame_generator_inspection` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1437 | False positive |
| `frame_coroutine_inspection` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1336 | False positive |
| `encoding_format_string_introspection` | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1335 | False positive |
| `encoding_getattr_concatenation` | encoding_obfuscation | False | - | False | False | False | Runtime (safe_globals stripped builtin) | 0.1525 | True negative |
| `builtins_wrap_close_globals` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1802 | False positive |
| `builtins_chr_self` | builtins_restoration | False | - | False | False | False | Compile-time (underscore rule) | 0.1526 | True negative |
| `builtins_os_builtins_import` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1346 | False positive |
| `frame_gi_frame_f_builtins` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1357 | False positive |
| `format_map_attrerror_leak` | format_string_attribute_access | False | - | True | False | False | Contained (safe execution) | 0.1378 | True negative |
| `adaptive_traceback_frame_walk` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1469 | False positive |
| `adaptive_getattr_string_concat` | subclasses_traversal | False | - | False | False | False | Runtime (safe_globals stripped builtin) | 0.2498 | True negative |
| `adaptive_format_map_runtime_template` | format_string_attribute_access | False | - | False | False | False | Runtime guard (safer_getattr) | 0.1395 | True negative |

### Confusion Matrix Breakdown

| Category | Definition | Count | Payloads |
|---|---|---|---|
| **True positive** | Flagged by static analyzer, escaped sandbox | 0 | *none* |
| **False positive** | Flagged by static analyzer, blocked by sandbox | 15 | `subclasses_tuple_base`, `subclasses_mro_catch_warnings`, `subclasses_int_hierarchy`, `globals_lambda_builtins`, `globals_closure_leak`, `globals_func_globals_alias`, `builtins_direct_canary_write`, `builtins_loader_recovery`, `frame_generator_inspection`, `frame_coroutine_inspection`, `encoding_format_string_introspection`, `builtins_wrap_close_globals`, `builtins_os_builtins_import`, `frame_gi_frame_f_builtins`, `adaptive_traceback_frame_walk` |
| **False negative** | Not flagged by static analyzer, escaped sandbox | 0 | *none* |
| **True negative** | Not flagged by static analyzer, blocked by sandbox | 5 | `encoding_getattr_concatenation`, `builtins_chr_self`, `format_map_attrerror_leak`, `adaptive_getattr_string_concat`, `adaptive_format_map_runtime_template` |

### Per-Technique Confusion Counts

| Technique | Total Payloads | TP | FP | FN | TN |
|---|---|---|---|---|---|
| `builtins_restoration` | 5 | 0 | 4 | 0 | 1 |
| `encoding_obfuscation`* | 1 | 0 | 0 | 0 | 1 |
| `format_string_attribute_access` | 3 | 0 | 1 | 0 | 2 |
| `frame_introspection` | 4 | 0 | 4 | 0 | 0 |
| `globals_access` | 3 | 0 | 3 | 0 | 0 |
| `subclasses_traversal` | 4 | 0 | 3 | 0 | 1 |

*\*Note: `encoding_obfuscation` has no dedicated detector and is not one of the 5 counted technique classes; it is included in the corpus for completeness as a baseline to evaluate dynamic evasion against `safe_globals`.*


### Research Takeaways: The Four-Layer Defense-in-Depth Model

The results demonstrate how `RestrictedPython` neutralizes known Python jailbreak techniques across four distinct defense layers:

1. **Compile-Time Underscore Policy**: `compile_restricted` inspects the AST and unconditionally rejects attribute access and variable names starting with `_` (`__class__`, `__subclasses__`, `__globals__`, `__builtins__`). This stops 10 out of 20 payloads before code ever executes.
2. **Compile-Time Restricted Name Policy**: Attributes that lack leading underscores but are critical for call stack navigation (specifically `f_back`, `f_globals`, `f_builtins`) are caught by RestrictedPython's restricted name blacklist, stopping all frame navigation attacks at compile time.
3. **Runtime Whitelist (`safe_globals`)**: Builtin functions like `getattr`, `eval`, `exec`, `open`, and modules like `os` or `sys` are entirely omitted from `safe_globals`. Dynamic evasion payloads (e.g. `getattr(object, '__sub' + 'classes__')`) bypass the static analyzer, but fail immediately at runtime with a `NameError: name 'getattr' is not defined`.
4. **Runtime Guards (`safer_getattr`)**: Vectors that hide attribute chains inside strings (such as `"{0.__class__}".format(...)` and `.format_map()`) bypass the compile-time underscore rule. However, when the string method executes, RestrictedPython's `safer_getattr` wrapper intercepts access and raises a `NotImplementedError`, preventing string formatting exploitation.

---

## Test Suite Execution

Run the complete automated test suite with `pytest`:

```bash
pytest -v
```

Tests cover:
- Detector unit tests with positive and negative AST snippets for each technique.
- Oracle correctness validation against a broken toy sandbox fixture and benign code.
- Dynamic prober lifecycle, timeouts, compile failures, and crash containment.
- End-to-end reporting and confusion matrix calculations.

---

## Project Structure

```text
SandboxEscapeFinder/
├── src/sandbox_escape_finder/
│   ├── __init__.py          # Public API exports
│   ├── static_analyzer.py   # Pure AST visitor detectors & Finding data models
│   ├── dynamic_prober.py    # Subprocess execution harness & capability checker
│   ├── oracle.py            # Deterministic canary lifecycle & verification oracle
│   ├── payloads.py          # Curated & attributed 20-payload research corpus
│   ├── reporting.py         # Static-vs-dynamic cross-referencing & metrics
│   └── config.py            # Minimal configuration dataclasses & safety defaults
├── tests/
│   ├── test_static_analyzer.py  # Positive/negative snippet tests for all 5 detectors
│   ├── test_dynamic_prober.py   # Subprocess isolation, timeouts, and error handling
│   ├── test_oracle.py           # Canary modification, deletion, and broken toy sandbox
│   ├── test_reporting.py        # Confusion matrix, blocking mechanism, and markdown tables
│   └── test_skeleton.py         # Package import and public API smoke tests
├── examples/
│   ├── quickstart.py        # End-to-end pipeline execution walkthrough
│   ├── run_comparison.py    # Standalone corpus comparison runner
│   └── corpus_sanity.py     # AST parse and detector coverage sanity check
├── docs/
│   └── DYNAMIC_EXECUTION_AND_ORACLE.md # Dynamic execution architecture & isolation guide
├── pyproject.toml           # PEP 621 package metadata & pinned dependencies
└── README.md                # Project documentation & empirical findings
```
