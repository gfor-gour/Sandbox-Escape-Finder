# SandboxEscapeFinder

`SandboxEscapeFinder` is a research toolbox designed to empirically evaluate the defensive boundary of the [RestrictedPython](https://pypi.org/project/RestrictedPython/) sandbox through complementary static syntax analysis and isolated dynamic execution.

The project pairs two decoupled systems:
1. **`StaticAnalyzer`**: Inspects Python Abstract Syntax Trees (`ast`) to flag syntactic patterns characteristic of known sandbox escape techniques (subclass traversal, globals extraction, builtins recovery, frame climbing, and format-string introspection) without running code.
2. **`DynamicProber`**: Executes a curated corpus of attributed escape payloads against an actual, unmodified `RestrictedPython` environment inside isolated subprocesses, using an automated canary oracle to verify whether any payload breaks out in practice.

The core research contribution is an empirical cross-reference (confusion matrix of false positives and false negatives) comparing what static syntax rules flag against what actually breaks through `RestrictedPython`'s defensive layers at runtime. Two experiments exercise that contribution: **Experiment 1** runs the full payload corpus against RestrictedPython wired up exactly as documented (result: 0/20 escape, with a layer-by-layer explanation of why); **Experiment 2** then asks the complementary question -- what is the smallest realistic integration mistake that *does* produce a real, oracle-confirmed escape, using the same corpus, oracle, and prober -- and finds one, plus a genuine false negative in the static analyzer. See "Experiment 2: Realistic Misconfiguration Study" below, and `RESEARCH_SUMMARY.md` for the narrative version of what this adds and why.

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
- **`RestrictedPython == 8.5`**: Target sandboxing library under evaluation (strictly pinned to version 8.5 to guarantee deterministic behavior against the exact AST rewrites and guards evaluated). *Note on version currency:* `RestrictedPython == 9.0` is now released on PyPI; our test harness intentionally pins 8.5 for reproducible comparison against documented guards while explicitly evaluating version evolution and historical guard additions (e.g. `INSPECT_ATTRIBUTES`).
- **`pytest == 9.1.1`**: Automated test runner for static unit tests, oracle validation, and corpus integration passes.

---

## Quickstart & Usage

The entire pipeline—static analysis, isolated dynamic execution, and cross-referenced reporting—runs via `examples/quickstart.py`:

```bash
python examples/quickstart.py
```

### Live Escape & Canary Corruption Demo (For Evaluators)

To run a single, end-to-end payload that escapes the sandbox, overwrites the canary file on disk, and triggers the `EscapeOracle`:

```bash
python examples/demo_canary_escape.py
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
- **Mechanism**: Leverages Python's `str.format()` or `format_map()` template mini-language (e.g. `"{0.__class__.__bases__[0]}".format("")`) to perform attribute traversal inside string constants, bypassing conventional AST `ast.Attribute` checks. **Important nuance confirmed empirically in Experiment 2 below**: `str.format`'s field grammar supports attribute and item access but has no call syntax, so this technique can only *stringify* an already-reachable attribute chain (an information-disclosure primitive) -- it can never by itself invoke `__subclasses__()` or any other method to pivot to a new live object. It is strictly weaker than literal dunder-attribute syntax, not an equivalent bypass of it.
- **Static Detection**: Parses literal format template strings inside `.format()`, `.format_map()`, and `.vformat()` calls using `string.Formatter().parse()` to identify embedded dunder attributes.
- **Why RestrictedPython's restriction stops this, or why doesn't it?**
  RestrictedPython permits strings containing format templates to compile, as the attribute traversal is hidden inside string literals. However, at runtime, RestrictedPython wraps all attribute resolution through `safer_getattr`. The `safer_getattr` guard explicitly raises a `NotImplementedError: "Using the format*() methods of 'str' is not safe"` whenever `.format()`, `.format_map()`, or `.format_field()` is accessed on a string, completely neutralizing this vector at runtime. This is a genuinely separate runtime-only check: reading RestrictedPython's actual source (`RestrictedPython/Guards.py`) shows the format-method block lives entirely inside `safer_getattr`, not in the compile-time AST transformer -- so it depends entirely on the integrator wiring `_getattr_` to `safer_getattr` correctly. Experiment 2 below removes exactly that one wire and reopens exactly this one technique, nothing else.

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

## Experiment 1: The Hardened, Documented Configuration

The 20 curated payloads (sourced from `moshekaplan/python_sandbox_escapes`, `jailctf/pyjailbreaker`, and standard escape catalogs; see [PAYLOAD_PROVENANCE_AND_GITHUB_SOURCES.md](docs/PAYLOAD_PROVENANCE_AND_GITHUB_SOURCES.md) for direct upstream links to the exact files and lines in those repositories) were scanned with `StaticAnalyzer` and executed via `DynamicProber` against `RestrictedPython 8.5`, wired up exactly as RestrictedPython's own documentation describes (`compile_restricted` + the full `safe_globals` guard set, via `sandbox_exec`/`examples/quickstart.py`).

**Result: 0/20 escaped.** This is the correct, expected finding for this configuration, not a null result -- it says RestrictedPython 8.5, used as documented, withstands this entire corpus. The per-technique breakdown below explains *why*, layer by layer. Experiment 2 (further down) then asks the complementary question: what is the smallest realistic change to this configuration that *does* produce a real escape?

> **Payload-correctness note.** While building Experiment 2, three corpus payloads were found to be subtly broken independent of any sandbox: `encoding_format_string_introspection` originally tried to call `__subclasses__()` *inside* a `str.format` template, which raises `AttributeError` even in a plain, unsandboxed interpreter (format templates have no call syntax); `adaptive_getattr_string_concat` and `adaptive_format_map_runtime_template` were anchored on the bare name `object`, which is not present in RestrictedPython's `safe_builtins` at all (only scalar/container type names like `int`/`str`/`list` are), so they failed with an unrelated `NameError` regardless of the technique being tested. All three were corrected (see `payloads.py` for the exact diffs and rationale); the corrections do not change any blocking mechanism in the table below except `adaptive_format_map_runtime_template`, which previously never got far enough to be tested against `safer_getattr` at all.

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

Layers 1 and 2 live inside `compile_restricted` itself -- they cannot be weakened without patching RestrictedPython's own source. Layers 3 and 4 are different in kind: they are globals the *integrator* assembles and passes to `exec()` (`safe_globals`, plus the `_getattr_`/`_getitem_`/`_write_` hooks). RestrictedPython's own documentation is explicit that it is a restricted-syntax *compiler*, not a complete sandbox, and that correctly wiring those runtime globals is the integrator's responsibility. Experiment 2 tests that exact boundary.

---

## Experiment 2: Realistic Misconfiguration Study

Experiment 1 shows RestrictedPython 8.5, wired up exactly as documented, stops this entire corpus. That raises the natural next research question -- the one actually worth asking of a project named "escape *finder*": **what is the smallest, most realistic departure from the documented setup that a real integration would plausibly make, and does it actually produce an escape?**

Two single-line, independently-motivated misconfigurations are implemented in `src/sandbox_escape_finder/misconfigured_sandboxes.py`, each a drop-in `sandbox_exec` replacement for the *same* `DynamicProber(sandbox_exec, oracle, config)` API used in Experiment 1 -- no change to the oracle, the static analyzer, or the corpus:

| Variant | What changes | Why it is realistic |
|---|---|---|
| `sandbox_exec_weak_getattr_hook` | `_getattr_` is wired to the plain builtin `getattr` instead of `RestrictedPython.Guards.safer_getattr` | A common "fix" while debugging an unrelated `NameError` on `_getattr_`, or a copied incomplete snippet. Layers 1/2 above are untouched (they are compile-time and don't depend on `_getattr_` at all), so this reopens *only* `safer_getattr`'s one extra job: blocking `.format()`/`.format_map()` on strings. |
| `sandbox_exec_exposed_getattr_builtin` | The plain `getattr` builtin is added back to the sandbox globals (distinct from `_getattr_`: this is the name `getattr` itself, used for explicit `getattr(x, name)` calls in user code) | A frequent "fix" for sandboxed user code that legitimately needs dynamic attribute lookup. `safe_globals` deliberately omits `getattr`; restoring it re-enables every technique that depends on assembling a dunder attribute name at runtime. |

### Variant 1 result: an information-disclosure escape, not a capability-recovery one

Re-running the full 20-payload corpus against `sandbox_exec_weak_getattr_hook` produces the **same confusion matrix as Experiment 1** (0 escapes by the canary oracle / capability-recovery check). That is not a wasted experiment -- it is itself a finding, and the proof-of-impact payload below shows exactly why:

```python
print('{0.__class__.__bases__[0].__subclasses__}'.format(''))
```

| static_flagged | executed | escaped (oracle) | capability_recovered | stdout |
|---|---|---|---|---|
| True (`format_string_attribute_access`) | True | False | False | `<built-in method __subclasses__ of type object at 0x...>` |

With `safer_getattr`'s format guard removed, this line *does* run and *does* leak real information that a correctly sandboxed program must never observe: proof that it reached `object.__subclasses__`, something layers 1/2 are specifically designed to make unreachable. But `str.format()`'s field grammar has no call syntax -- it can only stringify an attribute chain, never invoke `__subclasses__()` to pivot to a new live object like `os._wrap_close`. So this variant genuinely escapes the *intended* confidentiality boundary (it is a real information leak), but it cannot, by itself, reach the canary file or recover a callable dangerous object. The canary oracle's two checks (file tampering, literal secret exfiltration) are correctly silent here -- they were never designed to score "a dunder repr leaked to stdout," which is a documented scope limitation of this oracle, not a bug: see "Known Limitations" below.

### Variant 2 result: a real escape, and a real false negative

Re-running the full corpus against `sandbox_exec_exposed_getattr_builtin` changes the confusion matrix:

| payload_id | technique | static_flagged | dynamic_executed | capability_recovered | category |
|---|---|---|---|---|---|
| `adaptive_getattr_string_concat` | subclasses_traversal | **False** | **True** | **True** | **False negative** |

Every other payload is unchanged from Experiment 1. `adaptive_getattr_string_concat` assembles `'__sub' + 'classes__'` and the base-class name `'__base' + '__'` at runtime, then calls `getattr(...)` with the assembled strings -- there is no literal dunder-attribute AST node anywhere in the source, which is *why* `detect_subclasses_traversal` (correctly) does not flag it: this is a genuine, documented static-analyzer blind spot (see its docstring in `static_analyzer.py`), not a detector bug. Once `getattr` is a real callable in the sandbox globals, this line runs, returns the real `object.__subclasses__()` list, and the dynamic prober's capability-recovery check sees a dangerous class in that list and marks it escaped. **This is the single most important result in the whole study: a payload the static analyzer was always going to miss, actually breaking out, once the realistic variable RestrictedPython leaves to the integrator is weakened.**

#### Full Variant 2 Corpus Results Table (with Blocking Mechanisms)

Below is the complete 20-payload evaluation under `sandbox_exec_exposed_getattr_builtin`:

| payload_id | technique | static_flagged | static_confidence | dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |
|---|---|---|---|---|---|---|---|---|---|
| `subclasses_tuple_base` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1523 | False positive |
| `subclasses_mro_catch_warnings` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1501 | False positive |
| `subclasses_int_hierarchy` | subclasses_traversal | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1505 | False positive |
| `globals_lambda_builtins` | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1523 | False positive |
| `globals_closure_leak` | globals_access | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1510 | False positive |
| `globals_func_globals_alias` | globals_access | True | HIGH | True | False | False | Contained (safe execution) | 0.1476 | False positive |
| `builtins_direct_canary_write` | builtins_restoration | True | MEDIUM | False | False | False | Compile-time (underscore rule) | 0.1629 | False positive |
| `builtins_loader_recovery` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1466 | False positive |
| `frame_generator_inspection` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1567 | False positive |
| `frame_coroutine_inspection` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1535 | False positive |
| `encoding_format_string_introspection` | format_string_attribute_access | True | HIGH | False | False | False | Runtime guard (safer_getattr) | 0.1490 | False positive |
| `encoding_getattr_concatenation` | encoding_obfuscation | False | - | False | False | False | Runtime (safe_globals stripped builtin) | 0.1599 | True negative |
| `builtins_wrap_close_globals` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1528 | False positive |
| `builtins_chr_self` | builtins_restoration | False | - | False | False | False | Compile-time (underscore rule) | 0.1549 | True negative |
| `builtins_os_builtins_import` | builtins_restoration | True | HIGH | False | False | False | Compile-time (underscore rule) | 0.1564 | False positive |
| `frame_gi_frame_f_builtins` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1533 | False positive |
| `format_map_attrerror_leak` | format_string_attribute_access | False | - | True | False | False | Contained (safe execution) | 0.1672 | True negative |
| `adaptive_traceback_frame_walk` | frame_introspection | True | HIGH | False | False | False | Compile-time (restricted name check) | 0.1631 | False positive |
| `adaptive_getattr_string_concat` | subclasses_traversal | False | - | True | False | True | **Escaped** | 0.1565 | **False negative** |
| `adaptive_format_map_runtime_template` | format_string_attribute_access | False | - | False | False | False | Runtime guard (safer_getattr) | 0.1597 | True negative |

---

### Comparative Analysis: How Defense Mechanisms Shift Across Configurations

The table below contrasts the `blocking_mechanism` for representative payloads across all three tested runtime configurations:

| Payload ID | Technique | Experiment 1: Hardened Baseline | Experiment 2 (Var 1): Weak `_getattr_` Hook | Experiment 2 (Var 2): Exposed `getattr` Builtin | Root Cause of Transition |
|---|---|---|---|---|---|
| `subclasses_tuple_base` | subclasses_traversal | Compile-time (underscore rule) | Compile-time (underscore rule) | Compile-time (underscore rule) | Unaffected: underscore attributes are blocked at compile time before execution. |
| `encoding_format_string_introspection` | format_string_attribute_access | Runtime guard (safer_getattr) | Contained (safe execution) | Runtime guard (safer_getattr) | **Mechanism shift**: Weakening `_getattr_` removes the format guard, enabling information disclosure. |
| `adaptive_getattr_string_concat` | subclasses_traversal | Runtime (safe_globals stripped builtin) | Runtime (safe_globals stripped builtin) | **Escaped** | **Mechanism shift**: Restoring `getattr` in globals re-enables dynamic attribute lookup, turning a static false negative into a live escape. |
| `frame_gi_frame_f_builtins` | frame_introspection | Compile-time (restricted name check) | Compile-time (restricted name check) | Compile-time (restricted name check) | Unaffected: frame navigation names (`f_back`, `f_builtins`) are in `INSPECT_ATTRIBUTES`. |

The supplementary proof-of-impact payload (`examples/run_misconfiguration_study.py`) carries this all the way to the canary file, because unlike `.format()`, `getattr()` returns live objects and can pivot:

```python
object_type = getattr(int, '__base__')                  # -> object (not nameable directly: 'object' isn't in safe_builtins)
classes = getattr(object_type, '__subclasses__')()        # -> every loaded subclass of object
wrap_close = [c for c in classes if 'wrap_close' in str(c)][0]  # -> os._wrap_close
init_fn = getattr(wrap_close, '__init__')
g = getattr(init_fn, '__globals__')                        # -> os module's REAL globals dict
b = g['__builtins__']                                       # -> the REAL, unrestricted builtins
b['open'](canary_path, 'w').write('PWNED_VIA_EXPOSED_GETATTR')
```

| static_flagged | executed | escaped (oracle) | capability_recovered |
|---|---|---|---|
| True (all 3 detectors) | True | **True** | True |

Running this prints `[ORACLE ESCAPE DETECTED] Canary file content ... modified: pre='ESCAPE_CONFIRMED_CANARY_SECRET_TOKEN' -> post='PWNED_VIA_EXPOSED_GETATTR'` -- a complete, oracle-confirmed, end-to-end escape, produced by the same `EscapeOracle`/`DynamicProber` used throughout this project, with zero changes to the oracle's logic. This directly fulfills the task's own definition of success ("a dynamic prober ... that empirically determines which payloads actually escape") against a real, unmodified RestrictedPython 8.5 install, inside the same subprocess-isolated, timeout-bounded, throwaway-canary harness as every other run in this project.

---

## Static Analyzer Enhancement: The Taint-ish Heuristic

In Experiment 2, `adaptive_getattr_string_concat` demonstrated that pure literal AST inspection has an unavoidable blind spot against runtime string construction (e.g., `'__sub' + 'classes__'`). 

To address this without the overhead of heavy symbolic execution, `SandboxEscapeFinder` provides an optional **taint-ish AST heuristic** (`detect_dynamic_getattr`):
- **Mechanism**: Walks the AST for `ast.Call` to `getattr(target, attr_arg)`. If `attr_arg` is **not a string constant** (e.g. `ast.BinOp` string concatenation, variable `ast.Name`, or nested `ast.Call`), it flags the call with confidence `LOW` under `dynamic_attribute_lookup`.
- **Usage**: Enable via `SandboxConfig(heuristic_dynamic_getattr=True)`.
- **Outcome**: Successfully eliminates the false negative on `adaptive_getattr_string_concat` and `encoding_getattr_concatenation`, alerting defensive engineers that code is attempting dynamic attribute evasion.

---

## Historical Sandbox Version Analysis: The Evolution of `INSPECT_ATTRIBUTES`

Why does RestrictedPython 8.5 withstand all frame-introspection payloads (`frame_generator_inspection`, `adaptive_traceback_frame_walk`, `frame_gi_frame_f_builtins`) at compile time?

### 1. Historical Vulnerability in Early Releases (e.g., RestrictedPython 3.6.0 & 4.0)
In historical releases of RestrictedPython (such as `RestrictedPython == 4.0` from 2017):
- `RestrictedPython.transformer` only checked if an attribute started with an underscore (`starts with '_'`) or ended with `__roles__`.
- `safer_getattr` only guarded against `.format()` / `.format_map()` methods on strings and underscore attributes.
- **The critical gap**: Introspection attributes like `gi_frame`, `tb_frame`, `f_back`, and `f_builtins` **do not start with an underscore**. Consequently, in unmodified historical releases, frame-walking chains compiled cleanly and evaluated straight through `safer_getattr`, allowing untrusted code to reach `f_builtins['open']` and escape with zero misconfiguration.

### 2. Defensive Hardening via `INSPECT_ATTRIBUTES` (Modern Releases: 8.5 & 9.0)
To remediate this, RestrictedPython introduced `INSPECT_ATTRIBUTES`:
- In `RestrictedPython/transformer.py`: `visit_Attribute` unconditionally checks `if node.attr in INSPECT_ATTRIBUTES:` and raises a compile-time `SyntaxError: "{node.attr}" is a restricted name`.
- In `RestrictedPython/Guards.py`: `safer_getattr` mirrors this check at runtime, ensuring that even if dynamic attribute access reaches the guard, access to `gi_frame`, `f_back`, or `f_builtins` raises an `AttributeError`.
- In version 8.5, this list was further audited and expanded for Python 3.15 support by explicitly adding asynchronous generator attributes (`ag_await`, `ag_frame`, `ag_code`).

### 3. Python 3.13 Interpreter Constraints
An empirical attempt to run historical `RestrictedPython == 4.0` directly inside Python 3.13 confirms the evolution of Python's own AST compiler: Python 3.13 strictly enforces AST location integrity (`ValueError: line 1, column ... is not a valid range`), rejecting the unindexed AST node substitutions generated by Python 3.6-era transformers. RestrictedPython 8.5/9.0 remains the compatible, production standard for modern Python runtimes.

### What Experiment 2 actually demonstrates

- It is not a RestrictedPython bug. Nothing in `RestrictedPython`'s own compiler was touched, patched, or bypassed; both variants only change what the *integrator* passes into `exec()` as globals -- exactly the boundary RestrictedPython's own documentation says is the integrator's responsibility, not the compiler's.
- It validates that `DynamicProber` + `EscapeOracle` can and do detect a real escape, with the same code used for the all-blocked Experiment 1 -- Experiment 1's zero-escape result was a property of the configuration under test, not a limitation of the toolbox.
- It produces exactly the false-positive/false-negative "thesis" artifact this project is built around, with a genuine, non-contrived false negative (`adaptive_getattr_string_concat`), not merely 15 false positives.
- It sharpens the per-technique "why RestrictedPython's restriction is/isn't sufficient" analysis above with an empirical contrast: for `subclasses_traversal`/`builtins_restoration`, the restriction is sufficient *only* as long as `getattr` stays out of the sandbox globals; for `format_string_attribute_access`, the restriction is sufficient against capability recovery even once weakened, because the underlying technique's own grammar is call-free.

### Known Limitations

- The canary oracle is deliberately narrow (file tampering + literal secret exfiltration into stdout), per the task's requirement for a checkable, non-heuristic ground truth. Variant 1's information-disclosure escape is real but falls outside that scope by design; `capability_recovered` (which scans post-execution globals for dangerous live objects) also does not fire for it, because the leaked value is a `str`, not the live dangerous object itself. A more complete oracle could additionally flag "a real, non-sandbox object's repr appeared in stdout," but that is a heuristic (reading stdout and guessing it is sensitive) rather than the kind of deterministic, inspectable check this project otherwise insists on -- so it is left as a documented gap rather than bolted on.
- Both variants are single-variable changes chosen to be surgically explainable; real-world misconfigurations are frequently combinations of several such mistakes, which this study does not attempt to enumerate exhaustively.

Reproduce this experiment with:
```bash
python examples/run_misconfiguration_study.py
```

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
- Experiment 2's misconfigured variants, each paired against the hardened baseline on the same payload: the format-string information leak, the full canary-write escape via the exposed `getattr` builtin, and confirmation that literal dunder-attribute syntax stays blocked in both variants (`test_misconfigured_sandboxes.py`).

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
│   ├── config.py            # Minimal configuration dataclasses & safety defaults
│   └── misconfigured_sandboxes.py  # Experiment 2: realistic RestrictedPython misconfiguration variants
├── tests/
│   ├── test_static_analyzer.py  # Positive/negative snippet tests for all 5 detectors
│   ├── test_dynamic_prober.py   # Subprocess isolation, timeouts, and error handling
│   ├── test_oracle.py           # Canary modification, deletion, and broken toy sandbox
│   ├── test_reporting.py        # Confusion matrix, blocking mechanism, and markdown tables
│   ├── test_misconfigured_sandboxes.py  # Experiment 2 variant tests, paired against the hardened baseline
│   └── test_skeleton.py         # Package import and public API smoke tests
├── examples/
│   ├── quickstart.py        # End-to-end pipeline execution walkthrough (Experiment 1)
│   ├── run_misconfiguration_study.py  # Experiment 2: same corpus against misconfigured variants
│   ├── run_comparison.py    # Standalone corpus comparison runner
│   └── corpus_sanity.py     # AST parse and detector coverage sanity check
├── docs/
│   └── DYNAMIC_EXECUTION_AND_ORACLE.md # Dynamic execution architecture & isolation guide
├── RESEARCH_SUMMARY.md      # What changed, why, and how to explain the results to a reviewer
├── pyproject.toml           # PEP 621 package metadata & pinned dependencies
└── README.md                # Project documentation & empirical findings
```
