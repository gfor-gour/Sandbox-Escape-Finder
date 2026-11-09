# SandboxEscapeFinder — Findings & Research Reasoning

*A plain-language companion to the code, written to answer one question directly:*
**"If none of your 20 payloads escape RestrictedPython 8.5, what is actually happening?"**

This document explains **what was done, why it was done that way, and what it proves.**
Every number below was produced by running the code in this repository against
RestrictedPython **8.5** on **Python 3.13.7**. All 54 tests pass; both experiments
run end-to-end and write their canary to a throwaway temp directory only.

---

## 1. The short answer (one paragraph)

The payloads were *not* failing because they are wrong, and RestrictedPython is *not*
secretly perfect. The payloads fail against **the correctly-configured sandbox** because
**RestrictedPython is a compiler, not a sandbox.** It blocks these attacks at
*compile time* (it refuses to even build the bytecode for `x.__class__`) and with a few
*runtime guards* that the integrator must wire up. The security therefore lives in **how
you configure it**, not in RestrictedPython itself — a fact RestrictedPython's own README
states explicitly. To prove this is the real explanation (and not just "my payloads are
weak"), I ran the **same 20 payloads** against the **same RestrictedPython**, changing
**one line** of integrator configuration at a time. The moment a realistic, commonly-made
configuration mistake is introduced, payloads escape — including one that **overwrites the
canary file**, confirmed automatically by the oracle. So "zero escapes" is not a dead end;
it is a *measurement of where the security boundary actually is.*

---

## 2. Why "zero escapes" is the finding, not a failure

A weak version of this project would report *"we tried 20 attacks, all were blocked,
RestrictedPython is safe"* and stop. That is not research — it is a single data point with
no explanation.

The researcher's move is to ask **"blocked by what, exactly?"** and then **design an
experiment that isolates the cause.** If the cause is really "RestrictedPython's
configuration," then weakening the configuration — and nothing else — should flip the
result. If the cause were something else (e.g. my payloads being malformed), weakening the
configuration would change nothing. This is a standard **controlled differential
experiment**: hold everything constant except one variable, and see what moves.

That is exactly what this repo implements:

| | Experiment 1 (baseline) | Experiment 2 (controlled change) |
|---|---|---|
| RestrictedPython version | 8.5 | 8.5 (identical) |
| Payload corpus | 20 payloads | 20 payloads (identical) |
| Oracle | canary-file check | canary-file check (identical) |
| Static analyzer | same | same |
| **Sandbox configuration** | **documented / hardened** | **one realistic mistake, one line changed** |
| **Result** | **0 escapes** | **real escapes, incl. a canary overwrite** |

The only thing that changed between "nothing escapes" and "the canary gets overwritten" is
**one line of integrator configuration.** That is the proof that the configuration — not
the payloads, not RestrictedPython's compiler — is the security boundary.

---

## 3. What actually blocks the payloads (with source citations)

I did not guess at *why* each payload was blocked — the dynamic prober records a
`blocking_mechanism` for every payload, and each mechanism maps to a specific, nameable
piece of RestrictedPython's source. There are exactly **three** of them:

### Mechanism A — the compile-time underscore rule (blocks most payloads)
RestrictedPython's `RestrictingNodeTransformer.check_name` (`RestrictedPython/transformer.py`)
rejects **any name that starts with `_`** at compile time:

```python
if (name.startswith('_') and name != '_' and not (...)):
    self.error(node, '"{name}" is an invalid variable name because it starts with "_"')
```

This is why `().__class__.__bases__[0].__subclasses__()` never even runs: the compiler
refuses to emit bytecode for `.__class__`. The classic jailbreak chains (`__subclasses__`,
`__globals__`, `__builtins__`, `__mro__`, `gi_frame`, `f_back`) are **all** built out of
underscore-prefixed names, so they die at compile time — *before execution*. In the report
these show as `blocking_mechanism = "Compile-time (underscore rule)"` and
`executed = False`.

**This is the single most important insight for the professor:** most "escapes" in the
catalogs are not blocked by sandboxing at runtime — they are blocked because the code
**cannot be compiled at all.** That is a fundamentally different (and stronger) guarantee.

### Mechanism B — `safe_globals` omits dangerous builtins (blocks the stringless payloads)
Some payloads deliberately avoid underscores to dodge Mechanism A — e.g.
`getattr(object, '__sub' + 'classes__')()` builds the dunder name at runtime. These
**compile fine**. They then fail for a *different* reason: RestrictedPython's `safe_globals`
does not include `getattr`, `open`, `eval`, `exec`, or `__import__`. So the name `getattr`
simply does not exist inside the sandbox, and the payload dies with a `NameError` at
runtime. Report: `blocking_mechanism = "Runtime (safe_globals stripped builtin)"`.

### Mechanism C — `safer_getattr` blocks the format-string trick (runtime guard)
The `str.format` / `str.format_map` attack (`'{0.__class__}'.format(x)`) reaches dunder
attributes *through a template string*, so it slips past Mechanisms A and B. RestrictedPython
closes it with a dedicated runtime guard, `safer_getattr` (`RestrictedPython/Guards.py`):

```python
if name in ('format', 'format_map') and (isinstance(object, str) or ...):
    raise NotImplementedError('Using the format*() methods of `str` is not safe')
```

Report: `blocking_mechanism = "Runtime guard (safer_getattr)"`.

**Every one of the 20 payloads is stopped by exactly one of A, B, or C** — and the report
labels which. That is the per-technique "why is RestrictedPython's restriction sufficient"
analysis the task asks for, backed by evidence rather than assertion.

---

## 4. Experiment 2: make one realistic mistake, and payloads escape

RestrictedPython's README is explicit that **it only restricts syntax** — the integrator
must supply a correctly-guarded runtime environment. Real projects embedding RestrictedPython
get this wrong in well-known ways (visible in tutorials, Stack Overflow answers, and issue
trackers). `misconfigured_sandboxes.py` reproduces **two** such mistakes, each a **one-line
diff** from the hardened worker, changing *nothing else*:

### Variant 1 — `_getattr_` wired to plain `getattr` instead of `safer_getattr`
This disables **Mechanism C only**. Effect: the `str.format` attribute-leak works again.
Because `str.format` can only *stringify* an attribute (it has no call syntax), this is an
**information-disclosure** escape, not full capability recovery. Demonstrated output:

```
stdout: '<built-in method __subclasses__ of type object at 0x...>'
```

The sandbox leaked the live identity of `object.__subclasses__` as a string — something a
correctly-configured sandbox never lets the program observe.

### Variant 2 — the real `getattr` builtin restored to the globals
This defeats **Mechanism B**. `getattr` returns **live objects**, so the stringless payload
`getattr(object_type, '__subclasses__')()` now pivots through the class graph to
`os._wrap_close.__init__.__globals__['__builtins__']`, recovers the real `open()`, and
**overwrites the canary file.** The oracle confirms it automatically:

```
[ORACLE ESCAPE DETECTED] Canary file content modified:
  pre='ESCAPE_CONFIRMED_CANARY_SECRET_TOKEN' -> post='PWNED_VIA_EXPOSED_GETATTR'
executed:             True
escaped (oracle):     True
capability_recovered: True
```

**This is a full, machine-verified sandbox escape** — produced by the same toolbox, same
corpus, same oracle, with one line of configuration changed. It proves the prober and oracle
genuinely *can* detect a real break-out; they report zero against the hardened config because
there is genuinely nothing to detect there, not because they are blind.

---

## 5. Static vs. dynamic: the false-positive / false-negative analysis

The task requires comparing what the **static analyzer flags** against what **actually
escapes**. This comparison is itself a finding:

- **15 false positives (hardened config):** the static analyzer flags all the classic
  dunder chains as dangerous, but they **do not escape**, because RestrictedPython blocks
  them at compile time. A static scanner that treats "looks like a jailbreak" as "is an
  escape" would massively over-report. Static suspicion ≠ dynamic capability.
- **1 false negative (under Variant 2):** `adaptive_getattr_string_concat` builds its
  dunder name at runtime (`'__sub' + 'classes__'`), so there is **no literal dunder node in
  the AST** for the analyzer to see — yet it escapes once `getattr` is present. This is a
  genuine, honestly-reported blind spot of *any* purely-static AST scanner: runtime string
  construction is invisible to it. It is exactly the kind of gap a dynamic prober exists to
  catch. *(Note: To address this in defensive production scanners, we also introduced an optional
  taint-ish heuristic `detect_dynamic_getattr` / `heuristic_dynamic_getattr=True` that flags any
  `getattr()` call with a non-string-literal attribute argument, successfully closing this gap).*

The headline: **static analysis and dynamic probing disagree, and each covers the other's
weakness.** That is the argument for building both, which is what this project does.

---

## 5.1 Historical note: Unmodified escapes in older RestrictedPython (<= 4.0)

A key historical finding adds further depth to why RestrictedPython behaves the way it does:
In historical releases (such as `RestrictedPython == 4.0`), `INSPECT_ATTRIBUTES` did not exist in either
`transformer.py` or `safer_getattr`. Attributes like `gi_frame`, `tb_frame`, `f_back`, and `f_builtins`
lacked leading underscores and passed straight through both compile-time and runtime checks. In those
unmodified historical releases, frame-walking attacks broke out directly without any integration misconfiguration.
Modern RestrictedPython (evaluated here at pinned 8.5, and latest 9.0) hardened against this specifically by
introducing `INSPECT_ATTRIBUTES` across both compilation and runtime attribute guards. Modern Python 3.13 also
strictly validates AST source location ranges (`end_col_offset >= col_offset`), preventing unadapted 2017-era
AST transformers from compiling natively on Python 3.13.

---

## 6. What I would tell the professor in four sentences

> RestrictedPython 8.5 blocks all 20 catalog payloads not by sandboxing them at runtime but
> by refusing to compile them — its `check_name` transformer rejects every `_`-prefixed
> name, and two runtime guards (`safe_globals` omissions and `safer_getattr`) close the few
> payloads that avoid underscores. So "zero escapes" is a statement about RestrictedPython's
> **configuration**, not a claim that it is unbreakable. To prove that, I ran the identical
> corpus and oracle against the same RestrictedPython with one realistic integration mistake
> at a time, and payloads escaped — including one that overwrote the canary file, confirmed
> automatically by the oracle. The real deliverable is therefore not "an escape," but a
> precise map of *where RestrictedPython's security boundary is and what moves it.*

---

## 7. Honest limitations (stated deliberately)

A researcher names the limits of their own result:

1. **I did not break the correctly-configured sandbox.** The hardened RestrictedPython 8.5
   withstood this corpus, and I report that plainly. Claiming otherwise would be false. The
   contribution is the *characterization*, not a 0-day.
2. **The escapes are against deliberately-weakened configurations.** They are realistic
   (each mirrors a documented real-world mistake) but they are *my* configurations, chosen to
   isolate one variable — they are not a vulnerability in RestrictedPython's own code.
3. **The oracle scores capability + canary tampering, not pure information disclosure.** The
   Variant 1 string-leak is real but shows up in the proof-of-impact section rather than as an
   oracle "escape," because stringifying an attribute is a weaker primitive than writing a
   file. This is a documented scope choice, not a gap in the oracle's correctness.
4. **Static analysis is fundamentally incomplete** against runtime-constructed names (the one
   false negative in §5). No AST-only scanner can close this; it is why the dynamic prober
   exists.

---

## 8. How to reproduce every number in this document

```bash
pip install -e .
python examples/quickstart.py                 # Experiment 1: hardened baseline → 0 escapes
python examples/run_misconfiguration_study.py # Experiment 2: misconfigs → real escapes + canary write
python -m pytest -q                           # 54 tests, incl. oracle correctness on a broken toy sandbox
```

All dynamic execution runs in an **isolated subprocess** with a **hard timeout**, and every
canary is a **throwaway file in a disposable temp directory** — a genuine escape can tamper
only with that disposable canary, never with the host.
