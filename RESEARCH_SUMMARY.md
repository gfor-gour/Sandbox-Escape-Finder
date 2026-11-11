# Research Summary

Numbers below come from `python scripts/reproduce.py` (artifacts in `results/`). Files cited in backticks hold the evidence.

## Objective

Build a static analyzer that flags suspected sandbox-escape constructs in Python source, and a dynamic prober that runs an attributed payload corpus against a real, unmodified RestrictedPython and determines which payloads actually escape. The comparison of the two (false positives, false negatives) is the thesis; for each technique the project must explain why RestrictedPython's restriction does or does not stop it.

## Attempt 1

Twenty payloads from public catalogs ran against RestrictedPython 8.5 configured as documented. None escaped. The README explained, per technique, which layer stopped it, but when asked to show a file modified by a payload and caught as an escape, the project could not: the only result was "0/20", with no evidence that the prober and oracle could detect an escape at all.

## Attempt 2 (current state)

1. **Hardened baseline unchanged.** 0/20 escape (`results/experiment1.md`). Blocking mechanism per payload is recorded: 10 compile-time underscore rule, 4 compile-time restricted name, 2 stripped builtin, 2 `safer_getattr`, 2 contained at run time.
2. **Detection demonstrated.** With `getattr` added to the sandbox globals, `adaptive_getattr_string_concat` runs and recovers a dangerous class (`results/experiment2.md`), and a longer payload overwrites the canary file; the oracle confirms it (`results/demo_canary_diff.txt`, `python examples/demo_canary_escape.py`).
3. **Layer ablation.** Disabling one of four defense layers at a time and rerunning all 20 payloads (`results/ablation.md`, `results/ablation_heatmap.png`): 5 payloads escape only without layer A (compile-time underscore rule), 1 only without B (`INSPECT_ATTRIBUTES`), 2 only without C (stripped builtins), 0 only without D (`safer_getattr`), 12 under no single ablation. The layers overlap: A and B also remove their run-time twins inside `safer_getattr`, and D removes all of them, so the table shows dependence on a layer's checks, not a clean partition. Ablations A and B patch RestrictedPython in worker memory; ablations C and D change only the globals passed to `exec()`.
4. **Static analyzer upgrade.** A constant-folding pass resolves statically-determinable strings before the detectors run. The one documented false negative, `adaptive_getattr_string_concat`, is now flagged HIGH by the same detector as the literal case. A mutation fuzzer rewrites each payload's string literals and dunder attributes in 18 forms; the analyzer's caught/total count is in `results/analyzer_robustness.md`, against a literal-only count in `python examples/run_mutation_fuzz.py`.

## Four-sentence version

Against RestrictedPython 8.5 configured as documented, none of the 20 catalog payloads escape, and `results/experiment1.md` records which defense layer stops each. Disabling one layer at a time (`results/ablation.md`) shows 8 payloads escape under a single ablation (5 on the compile-time underscore rule, 1 on `INSPECT_ATTRIBUTES`, 2 on stripped builtins) and 12 under none, and the oracle confirmed a canary overwrite when `getattr` was added to the sandbox globals. A constant-folding pass in the static analyzer now flags the one payload it previously missed, and a fuzzer checks that fix against obfuscated variants of every payload (`results/analyzer_robustness.md`). The historical-version comparison is not run, so the project makes no claim about older RestrictedPython releases.

## Still open

- **Historical versions (not run).** No `scripts/version_sweep.py` or `results/version_sweep.png` exists. On the Python 3.13 used here, pip offers RestrictedPython 7.4, 8.0–8.5, 9.0, 4.0 and 3.x but not 5.x or 6.x; a sweep needs more than one interpreter. `tests/test_version_sweep.py` is a skipped template.
- **Layer combinations.** Each ablation changes one layer; pairs are not measured, so the 12 payloads that never escape are not split into "needs two layers" and "never escapes".
- **Oracle scope.** The format-string leak under ablation D is not counted as an escape.
- **Demo contrast.** `examples/demo_canary_escape.py` runs only the misconfigured sandbox and prints to stdout; the hardened-versus-misconfigured contrast and the saved diff come from separate code in `scripts/reproduce.py`.

## Honest limitations

1. **The correctly-configured sandbox was not broken.** RestrictedPython 8.5 withstood this corpus. The contribution is the characterization of where its boundary is, not a vulnerability.
2. **The escapes are against deliberately weakened configurations.** Each mirrors a plausible integration mistake, but the configurations are this project's, chosen to isolate one variable; they are not a flaw in RestrictedPython's own code. Ablations A and B patch RestrictedPython in worker memory.
3. **The oracle scores capability recovery and canary tampering, not information disclosure.** The Variant 1 format-string leak is real but is reported separately, not as an oracle escape.
4. **Static analysis is incomplete against runtime-constructed names.** Constant folding resolves only statically-resolvable strings; a name that depends on input (`getattr(x, user_input)`) is not resolved and is reported only by the optional LOW-confidence heuristic.
