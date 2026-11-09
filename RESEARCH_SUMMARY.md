# Research Summary: What Changed, and Why

This document explains, in plain language, what was added to `SandboxEscapeFinder`
after your professor's feedback, why "zero escapes" was never actually a
failure, and what the new work adds. It's written for you to read before your
next meeting with him -- the short version you can say out loud is in the
last section.

## 1. The problem he raised

> "If your sandbox_escape_finder isn't escaping any of the payloads, what's
> happening?"

That's a completely fair question to ask of a project named "escape
*finder*" that finds zero escapes. But it has a precise, defensible answer,
and the fix isn't to fake an escape -- it's to show you understand exactly
*why* there were zero, and then go find the real boundary of that result.

## 2. Why zero escapes was the *correct* result (not a bug)

Your `sandbox_exec` wires up `RestrictedPython` exactly the way its own
documentation describes: `compile_restricted()` plus the complete
`safe_globals` runtime guard set (`safer_getattr`, `full_write_guard`, etc.).
RestrictedPython 8.5, used exactly as documented, is supposed to stop this
whole class of known techniques -- that's the entire point of the library.
Running all 20 catalog payloads against it and getting 0 escapes is the
**expected, correct outcome for that specific configuration**. It's the same
kind of result as fuzzing a well-reviewed `argon2` implementation and finding
no hash collisions: a clean result, not a sign the fuzzer is broken.

The project's existing README already explains, technique by technique,
*which* of RestrictedPython's defense layers stops each payload (compile-time
underscore rejection, compile-time restricted-name rejection, the absent
`getattr`/`eval`/`open` builtins, and the `safer_getattr` runtime guard). That
explanation was already correct and is the real deliverable the task asked
for ("explain, for each technique, why RestrictedPython's specific
restriction is or isn't sufficient").

**What was missing** was the natural next question a researcher asks after a
clean result: *what's the smallest realistic thing that would flip this?*
That's what got added.

## 3. What RestrictedPython itself says about this boundary

RestrictedPython's own documentation is explicit: it is a **restricted-syntax
compiler**, not a complete sandbox. It restricts what source code is allowed
to *say* (no `_`-prefixed names, no restricted attribute names at compile
time). It does **not** control what globals get handed to `exec()` at
runtime -- that part (`safe_globals`, the `_getattr_`/`_getitem_`/`_write_`
guard functions) is explicitly the *integrator's* responsibility. Every
real-world RestrictedPython escape writeup you'll find online is really a
story about that second part going wrong, not about the compiler itself
being broken.

So the genuinely interesting research question isn't "can I break
RestrictedPython's compiler" (you can't, and shouldn't try -- that's not
what this task is about) -- it's "what does a realistic integration mistake
in that second part look like, and does my toolbox actually catch it when it
happens?"

## 4. What was added: Experiment 2

Two new, narrow, one-line-diff `sandbox_exec` variants were added in
`src/sandbox_escape_finder/misconfigured_sandboxes.py`. Each plugs into the
exact same `DynamicProber(sandbox_exec, oracle, config)` API the task
requires -- nothing about the oracle, the static analyzer, or the payload
corpus changed.

**Variant 1 -- `sandbox_exec_weak_getattr_hook`:** `_getattr_` is pointed at
the plain `getattr` builtin instead of `RestrictedPython.Guards.safer_getattr`.
This is a very plausible mistake -- e.g. while debugging an unrelated
`NameError` on `_getattr_`, or copying an incomplete tutorial snippet.

**Variant 2 -- `sandbox_exec_exposed_getattr_builtin`:** the plain `getattr`
builtin itself is added back to the sandbox's globals. `safe_globals`
deliberately leaves it out; restoring it for "convenience" (sandboxed code
that legitimately needs dynamic attribute lookup) is also a very plausible
real mistake.

Both were verified by actually reading RestrictedPython's source
(`RestrictedPython/transformer.py`, `RestrictedPython/Guards.py`) to confirm
exactly which layer each change does and doesn't touch, rather than guessing.

### What happened when the same 20-payload corpus ran against them

- **Variant 1**: the confusion matrix came back identical to the hardened
  baseline -- 0 escapes by the canary oracle. But a dedicated proof payload
  showed this isn't nothing: with the guard removed, `str.format()` now
  genuinely leaks the fact that sandboxed code reached `object.__subclasses__`
  (an internal that should be completely unreachable) into stdout. It turns
  out `str.format()`'s template grammar can only *stringify* an attribute
  chain, never *call* a method -- so this is a real information-disclosure
  escape, but it structurally can't pivot any further on its own. That's a
  genuine, specific, defensible finding about *why* this technique class is
  capped at information disclosure, not full compromise -- discovered by
  actually testing it, not by assumption.

- **Variant 2**: one of the 20 corpus payloads, `adaptive_getattr_string_concat`
  (which assembles the string `'__subclasses__'` at runtime specifically to
  dodge the static analyzer), **actually ran and recovered a dangerous
  capability** -- a real escape, and a real false negative (the static
  analyzer correctly didn't flag it, and it correctly did escape). A
  follow-up payload carried this all the way to a complete,
  oracle-confirmed canary file write: `[ORACLE ESCAPE DETECTED] Canary file
  content ... modified: pre='ESCAPE_CONFIRMED_CANARY_SECRET_TOKEN' ->
  post='PWNED_VIA_EXPOSED_GETATTR'`, using the exact same `EscapeOracle` and
  `DynamicProber` machinery as every other run in the project.

### A smaller but important side-finding: fixing the corpus itself

While building this, three of the original 20 payloads turned out to be
subtly broken *independent of any sandbox* -- things that would fail even in
a plain, unsandboxed Python shell:

- `encoding_format_string_introspection` tried to call `__subclasses__()`
  *inside* a `str.format` template. Format templates have no call syntax, so
  this always raised `AttributeError`, sandbox or not. Fixed by moving the
  call outside the template.
- `adaptive_getattr_string_concat` and `adaptive_format_map_runtime_template`
  were both anchored on the bare name `object`, which isn't actually present
  in RestrictedPython's `safe_builtins` (only type names like `int`/`str`
  are). Both always failed with an unrelated `NameError`, which meant they
  were never really testing the technique they claimed to test. Fixed by
  anchoring on `int` (and, for the subclasses payload, climbing via
  `int.__base__` to reach the full class graph).

This matters because it's exactly the kind of thing the false-positive/
false-negative table is supposed to catch, and it's honest to say so rather
than quietly leaving stale payloads in a "verified" corpus.

## 5. How this answers the professor's actual concern

He wasn't really asking "why is the number zero" -- he was asking "do you
actually understand what you built well enough to know whether zero is
right, and can you push on it like a researcher would." Experiment 2 answers
that directly:

- It proves the toolbox's dynamic prober and oracle genuinely work end to
  end on a real escape, not just on the all-blocked case.
- It shows the boundary isn't "RestrictedPython is unbreakable" -- it's "the
  documented, correctly-configured library withstands this corpus; two
  narrow, realistic integration mistakes reopen some of it, and we measured
  exactly how much."
- It produced a real false negative (not contrived), which is the thing the
  task explicitly says is the actual deliverable ("this comparison is the
  thesis, not a side note").

## 6. How to explain this out loud, in four sentences

> "The static analyzer and dynamic prober work correctly -- against
> RestrictedPython configured exactly as documented, zero of our twenty
> catalog payloads escape, and I can explain which of four defense layers
> stops each one. RestrictedPython's own docs say it's a compiler, not a
> full sandbox, and that correctly wiring the runtime globals is on the
> integrator -- so I built a second experiment that reproduces two narrow,
> realistic integration mistakes people actually make, using the exact same
> oracle and prober. One of those mistakes lets a payload the static
> analyzer was always going to miss actually escape all the way to a file
> write, which I verified end-to-end; the other reopens a real information
> leak but can't go further, because of a grammar limit I confirmed by
> testing it directly, not assuming it."

## 7. Where to look

- `README.md` -- "Experiment 1" (unchanged baseline, now with a payload
  correctness note) and "Experiment 2: Realistic Misconfiguration Study"
  (new), including full result tables.
- `src/sandbox_escape_finder/misconfigured_sandboxes.py` -- the two variants,
  each documented with exactly what RestrictedPython source it relies on.
- `examples/run_misconfiguration_study.py` -- runnable end-to-end demo of
  both variants plus both proof-of-impact payloads.
- `tests/test_misconfigured_sandboxes.py` -- 9 tests, each pairing a
  misconfigured variant against the hardened baseline on the same payload.
