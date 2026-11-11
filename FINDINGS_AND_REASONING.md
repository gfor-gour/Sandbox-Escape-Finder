# SandboxEscapeFinder — Findings and Reasoning

Question this answers: **if none of the 20 payloads escape RestrictedPython 8.5 as documented, what is happening?** Numbers come from `python scripts/reproduce.py` (artifacts in `results/`); environment: RestrictedPython 8.5, Python 3.13.

## 1. Short answer

RestrictedPython is a compiler plus a set of runtime guards the integrator wires up. Against the documented wiring every payload is blocked, mostly at compile time. Weakening one piece at a time and rerunning the same corpus, oracle and analyzer locates which piece blocks which payload (§5.2) and shows a real, oracle-confirmed escape when `getattr` is exposed (§4).

## 2. Controlled comparison

| | Experiment 1 | Experiment 2 (variants, ablation) |
|---|---|---|
| RestrictedPython | 8.5 | 8.5 |
| Corpus, oracle, analyzer | same 20 payloads, same oracle | same |
| Sandbox configuration | documented | one layer or one global changed |
| Result | 0/20 escape (`results/experiment1.md`) | escapes only under specific changes (`results/ablation.md`, `results/experiment2.md`) |

## 3. What blocks the payloads

`results/experiment1.md` records the blocking mechanism per payload: 10 compile-time underscore rule, 4 compile-time restricted name, 2 stripped builtin, 2 `safer_getattr`, 2 contained at run time.

- **Underscore rule** — `RestrictingNodeTransformer.check_name` rejects names starting with `_` (`transformer.py:409`) and `visit_Attribute` rejects such attributes (`:865`). `.__class__`, `__subclasses__`, `__globals__`, `__builtins__` never compile.
- **Restricted names** — `visit_Attribute` rejects names in `INSPECT_ATTRIBUTES` (`transformer.py:70`, `:877`), e.g. `gi_frame`, `f_back`, `f_globals`; `safer_getattr` re-checks at run time (`Guards.py:268`).
- **Stripped builtins** — `safe_builtins` omits `getattr`, `open`, `eval`, `exec`, `__import__` (`Guards.py:111`); payloads that build a dunder name at runtime compile but raise `NameError`.
- **`safer_getattr`** — raises for `format` / `format_map` on `str` (`Guards.py:255`), blocking template-string attribute walks.

## 4. Realistic misconfigurations

- **Variant 1, `_getattr_` = plain `getattr`.** Removes `safer_getattr`'s checks. 0 oracle escapes (`results/experiment2.md`), but `'{0.__class__.__bases__[0].__subclasses__}'.format('')` now prints `<built-in method __subclasses__ ...>`. `str.format` has no call syntax, so it can only stringify an attribute chain; it cannot pivot to a new object. The oracle does not score this.
- **Variant 2, `getattr` added to the globals.** `adaptive_getattr_string_concat` runs and recovers a dangerous class (`results/experiment2.md`: 1 true positive, 17 false positives, 0 false negatives). `python examples/demo_canary_escape.py` follows `int` to `object` to `os._wrap_close.__init__.__globals__['__builtins__']['open']` and overwrites the canary; `results/demo_canary_diff.txt` holds the diff.

## 5. Static versus dynamic

Hardened configuration (`results/experiment1.md`): 0 true positives, 18 false positives, 0 false negatives, 2 true negatives. A scanner that reads "looks suspicious" as "is an escape" over-reports because the compiler rejects the code first.

Documented false negative, now closed:

| `adaptive_getattr_string_concat` | static verdict | outcome under Variant 2 |
|---|---|---|
| before constant folding (`SandboxConfig(constant_folding=False)`) | unflagged | escapes: false negative |
| after (default) | `subclasses_traversal`, HIGH | escapes: true positive |

`constant_folding.py` rewrites statically-determinable string expressions to literals before the existing detectors run, so the HIGH finding comes from the unchanged literal detector, not a new heuristic. The optional heuristic (`heuristic_dynamic_getattr=True`, off by default) still reports LOW for names that stay unresolved. Mutation testing: `results/analyzer_robustness.md` (caught/total over 18 obfuscation forms of every payload); `python examples/run_mutation_fuzz.py` adds the per-form table and the literal-only count.

### 5.1 Historical note — not yet empirically verified

Claim, unverified: in older releases (for example 4.0) `INSPECT_ATTRIBUTES` was absent, so frame-walking payloads worked without any misconfiguration. No version sweep exists in this repository (no `scripts/version_sweep.py`, no `results/version_sweep.png`), and an attempt to run 4.0 on Python 3.13 is not recorded in any artifact. On the Python 3.13 used here `pip index versions RestrictedPython` offers 9.0, 8.5-8.0, 7.4, 4.0 and 3.x, not 5.x or 6.x. `tests/test_version_sweep.py` is a skipped template for running one payload under an interpreter set in `SEF_HISTORICAL_PYTHON`.

### 5.2 Defense-layer ablation

`results/ablation.md` (full table with the Hardened column, all "safe"), `results/ablation_heatmap.png`. Each column disables one layer. Layer A: compile-time underscore rule (plus the underscore check in a copy of `safer_getattr`); B: `INSPECT_ATTRIBUTES` emptied in `transformer` and `Guards`; C: real `builtins` as `__builtins__`; D: `_getattr_` = plain `getattr`.

| payload | A | B | C | D |
|---|---|---|---|---|
| subclasses_tuple_base | escapes | safe | safe | safe |
| subclasses_mro_catch_warnings | escapes | safe | safe | safe |
| subclasses_int_hierarchy | escapes | safe | safe | safe |
| globals_lambda_builtins | escapes | safe | safe | safe |
| builtins_chr_self | escapes | safe | safe | safe |
| frame_generator_inspection | safe | escapes | safe | safe |
| encoding_getattr_concatenation | safe | safe | escapes | safe |
| adaptive_getattr_string_concat | safe | safe | escapes | safe |
| the other 12 payloads | safe | safe | safe | safe |

5 payloads are load-bearing only on layer A; 1 only on B; 2 only on C; 0 only on D; 12 run safely under every single ablation; 0 need more than one layer disabled (only single-layer ablations were run).

Reading the table: the layers overlap. A and B each remove a compile-time check and its run-time twin in `safer_getattr`; D removes every check in `safer_getattr`. D's 0 follows from the oracle's scope (the D gadget leaks a string and recovers no object) and from compile-time layers still blocking everything else. Ablations A and B patch RestrictedPython in the worker process's memory; the library files are unmodified.

## 6. Four-sentence version

Against RestrictedPython 8.5 configured as documented, none of 20 catalog payloads escape, and the blocking mechanism of each is recorded in `results/experiment1.md`. Disabling one defense layer at a time shows 8 payloads escape under a single ablation (5 on the compile-time underscore rule, 1 on `INSPECT_ATTRIBUTES`, 2 on stripped builtins) and 12 under none (`results/ablation.md`), and exposing `getattr` produced an oracle-confirmed canary overwrite. A constant-folding pass now flags the one payload the static analyzer previously missed, with mutation testing checking the fix against obfuscated variants. The historical-version comparison is not run.

## 7. Honest limitations

1. **The correctly-configured sandbox was not broken.** RestrictedPython 8.5 withstood this corpus; the contribution is the characterization, not a vulnerability.
2. **The weakened configurations are deliberate choices.** Each mirrors a plausible integration mistake but is chosen by this project to isolate one variable; none is a flaw in RestrictedPython's own code.
3. **The oracle scores capability recovery and canary tampering, not pure information disclosure.** The Variant 1 string leak is real and reported separately.
4. **Static analysis is incomplete against runtime-constructed names.** Constant folding resolves only statically-resolvable strings; genuinely dynamic names (`getattr(x, user_input)`) are not resolved and rely on the LOW-confidence heuristic.
5. **Layers overlap and only single ablations were run** (§5.2); two-layer combinations are unmeasured.
6. **Experiment 3 (historical versions) was not run** (§5.1).

## 8. Reproduce

```bash
pip install -e ".[dev]"
python -m pytest -q
python scripts/reproduce.py        # or: make reproduce
python examples/demo_canary_escape.py
```
