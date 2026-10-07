# Task SandboxEscapeFinder: Agent Context Document + Initial Prompts

---

## Context Document (give this to the agent first, as background/system context)

### What we are building

We are building `SandboxEscapeFinder`, a small Python research toolbox with two parts:

1. **`StaticAnalyzer`** — scans arbitrary Python source code using AST (Abstract
   Syntax Tree) analysis and flags code that looks like it is attempting a
   known "sandbox escape" technique (e.g. reaching `os` via
   `().__class__.__bases__[0].__subclasses__()`).
2. **`DynamicProber`** — takes a corpus of actual escape-attempt payloads and
   runs them against a real, unmodified `RestrictedPython` sandbox instance,
   using an automated oracle to determine which payloads *actually* break out
   of the sandbox in practice.

The end deliverable compares the two: which payloads the static analyzer
*flagged* vs. which payloads *actually escaped* when run. This comparison
(false positives / false negatives) is the core research contribution, not a
side note.

### Why we are doing this

Many real systems (code-interpreter tools inside AI agents, online judges,
notebook services) run untrusted or LLM-generated Python inside a "restricted"
execution environment. These sandboxes are routinely broken using well-known
Python introspection tricks. `RestrictedPython` itself documents that it is
**not** a full security boundary on its own — it restricts syntax, not runtime
object graph traversal. This task is about empirically characterizing that
gap: what a static scanner *can* catch by reading code vs. what actually works
when executed, against one specific, well-known sandbox.

This is explicitly **defensive security research**: we are evaluating the
robustness of an existing open-source project, not attacking a live/production
system, and not building a tool meant to break real deployed services.

### Scope and non-goals

- We are **not** trying to find a novel zero-day. We are reproducing and
  cataloging **known, publicly documented** escape technique classes against
  `RestrictedPython`, which is itself explicit that it needs to be paired with
  other protections (seccomp, containers, etc.) in production.
- We are **not** building a general-purpose Python sandboxing product.
- We are **not** testing against any live, third-party, or production system.
  All dynamic execution happens against a local, throwaway instance of
  `RestrictedPython` that we control.
- The target of any "successful escape" is a canary artifact (a file path or
  environment variable) that we define ourselves, pointed at a throwaway
  location — never a real system path, never anything on the host that
  matters.

### Hard safety constraints (non-negotiable)

1. **Isolation is mandatory.** Every payload execution happens inside a
   subprocess (or equivalent isolated context — e.g. a container or restricted
   temp directory), never directly in the main process, and never with access
   to real file paths, real env vars, or network access.
2. **Canary targets must be throwaway.** If a payload "succeeds" at escaping,
   the only thing it can touch is a canary file/variable we created
   specifically for that test run, in a disposable temp directory that gets
   cleaned up.
3. **No payload should ever be run against anything other than our own local
   `RestrictedPython` instance.** Never point any payload at a real system
   command, a real network endpoint, or anything outside the test fixture.
4. **Timeouts on every dynamic execution.** A payload that hangs must be
   killed after a short timeout — don't let a single bad payload block the
   whole corpus run.
5. **Reproducibility.** Any randomness (payload ordering, sampling) must be
   seeded via `config`.

### What the agent *can* do

- Read and use `RestrictedPython`'s actual public API (`compile_restricted`,
  `safe_globals`, etc.) — don't reinvent or mock the sandbox itself; the whole
  point is testing the *real* library.
- Use Python's built-in `ast` module for all static detection — no regex-only
  matching, no external "security scanner" dependency that hides the logic
  from us (we need to be able to explain every detector).
- Pull real payloads from the two named public catalogs
  (`jailctf/pyjailbreaker`, `moshekaplan/python_sandbox_escapes`) and attribute
  each one to its source technique in a comment/metadata field.
- Use `subprocess`, `multiprocessing`, or a similar standard-library isolation
  mechanism for dynamic execution — keep this simple and auditable rather than
  reaching for a heavyweight sandboxing framework.
- Propose a config schema (JSON/dict) but keep it minimal and justify every
  field.

### What the agent should avoid

- **Do not write payloads that target real system paths, real credentials, or
  anything outside the isolated test fixture**, even as "examples."
- **Do not add unnecessary abstraction layers** (plugin systems, factory
  patterns, generic "technique registry" frameworks) before there's a concrete
  need for them — start with a direct, readable implementation; add structure
  only when a second/third detector or payload type clearly needs it.
- **Do not use regex as the primary detection mechanism.** Regex may appear
  only as a tiny supplementary check if truly justified, but the primary
  mechanism must be AST traversal.
- **Do not fabricate or hand-wave the oracle.** The oracle must be a real,
  checkable condition (e.g. "does file X exist and contain marker Y"), not a
  heuristic guess or an LLM-based judgment call.
- **Do not skip the false-positive/false-negative comparison.** This is a
  required deliverable, not an optional nice-to-have.
- **Do not write filler code** — no unused helper functions, no speculative
  "future extensibility" hooks that aren't used by the current detectors/
  payloads, no code that exists only to look thorough.
- **Do not silently swallow exceptions** during dynamic execution — a payload
  that crashes the sandbox is itself a result worth recording, not something
  to catch-and-ignore.

### Important things to focus on while implementing

- **Explainability over cleverness.** Every detector and every oracle check
  must be simple enough that we (the human) can read it once and explain it
  in a review. If a piece of code needs a paragraph of comments to justify
  why it's structured the way it is, it's probably too clever — simplify it.
- **Each finding/report entry must be self-contained and inspectable** — i.e.
  you should be able to print one finding or one report row and understand
  exactly what matched and why, without cross-referencing other code.
- **Treat the false-positive/false-negative table as the thesis of the
  project** — everything else (detectors, prober, payload corpus) exists to
  produce that table honestly.
- **Keep the static analyzer and the dynamic prober genuinely decoupled** —
  the static analyzer should never need to run code, and the prober should
  never need to parse AST. They are combined only at the reporting/comparison
  stage.
- **Document, for each implemented technique, why `RestrictedPython`'s
  specific restrictions do or don't stop it** — this is explicitly required
  for the final review ("You can explain, for each technique, why
  RestrictedPython's specific restriction is (or isn't) sufficient against
  it").

### Definition of done (for this task specifically)

- `StaticAnalyzer.scan(source_code)` returns findings for ≥5 named technique
  classes, each with technique name, AST node location, and confidence.
- `DynamicProber.run(payload_corpus)` executes ≥10 attributed payloads
  against a real `RestrictedPython` instance, safely isolated, and returns a
  report with static verdict, execution result, oracle verdict, and timing
  per payload.
- A results table cross-referencing static-flagged vs. dynamically-escaped
  payloads exists and is interpretable.
- Tests cover: detector unit tests (positive/negative snippets), an
  oracle-correctness test against an intentionally-broken toy sandbox
  fixture, and one full end-to-end corpus run.
- Package installs via `pip install -e .`, has a working
  `examples/quickstart.py`, and a README explaining install, usage, each
  technique, the oracle design, and the results table.

---
