"""Realistic RestrictedPython misconfiguration variants (research extension).

`dynamic_prober.sandbox_exec` wires up RestrictedPython exactly as its own
documentation and examples describe: `compile_restricted` plus every runtime
guard from `safe_globals`/`RestrictedPython.Guards`. Running the full 20-payload
corpus (see `payloads.py`) against that hardened configuration produces zero
escapes -- see README.md, "Experiment 1". That is a correct and expected
result, not a null result: it says RestrictedPython 8.5, used as documented,
withstands this corpus.

RestrictedPython's own README is explicit that it is a compiler, not a
complete sandbox: it restricts *syntax*, and the integrator is responsible for
supplying a correctly-guarded runtime environment. The two sandbox_exec
variants below each reproduce one specific, narrow, commonly-made integration
mistake -- the kind that shows up in tutorials, Stack Overflow answers, and
real issue trackers for projects embedding RestrictedPython -- and change
*nothing else*. Each is a one-line diff from the hardened `_WORKER_SCRIPT` in
`dynamic_prober.py`. Running the same corpus, same oracle, and same static
analyzer against them is "Experiment 2": it demonstrates that the toolbox's
dynamic prober and oracle can and do detect real escapes once the one
realistic variable that RestrictedPython explicitly leaves to the integrator
is weakened, without ever touching RestrictedPython's own compiler code.

Both variants share `dynamic_prober._run_worker_script` for subprocess
isolation, disposable work directories, and the hard timeout -- only the
in-subprocess worker script (i.e. which RestrictedPython globals get wired up)
differs from the hardened baseline.

Variant 1 -- weak `_getattr_` hook
-----------------------------------
RestrictedPython's AST transform rewrites every `a.b` access in compiled code
into a call to whatever the globals provide as `_getattr_`. Dunder attribute
*names* (`a.__class__`) are rejected by the compiler itself regardless of
`_getattr_`, so this variant does not reopen those. But non-underscore
attribute names -- notably `.format` / `.format_map` on a string -- compile
and reach `_getattr_` at runtime. The hardened config points `_getattr_` at
`RestrictedPython.Guards.safer_getattr`, which has a specific check that
raises `NotImplementedError` for string-formatting methods precisely because
`.format()`/`.format_map()` can be used to reach dunder attributes through a
template string. If an integrator instead wires `_getattr_` to the plain
builtin `getattr` -- e.g. while debugging an unrelated `NameError` on
`_getattr_`, or copying an incomplete snippet -- that specific check disappears
and format-string attribute traversal (`'{0.__class__}'.format(...)`,
`format_map`) works again.

Variant 2 -- `getattr` exposed as a plain global
--------------------------------------------------
`safe_globals` deliberately omits the `getattr` builtin itself (distinct from
the `_getattr_` guard hook above, which only fires for `a.b` syntax).
Explicit `getattr(x, name)` *calls* are ordinary function calls; RestrictedPython's
compiler has no reason to touch them, so whether they work depends entirely on
whether `getattr` is present in the globals dict as a callable. If an
integrator adds `getattr` back for convenience (a frequent "fix" for user
code that legitimately needs dynamic attribute lookup), every static-analysis
blind spot that relies on constructing a dunder attribute name at runtime
(e.g. `getattr(object, '__sub' + 'classes__')`) becomes reachable, because
plain `getattr` enforces no underscore policy at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import _WORKER_SCRIPT, _run_worker_script

# --- Variant 1: _getattr_ wired to plain getattr instead of safer_getattr. ---
# Single-line diff from the hardened _WORKER_SCRIPT: drops the safer_getattr
# import/usage and assigns the builtin getattr directly.
_WORKER_SCRIPT_WEAK_GETATTR_HOOK = _WORKER_SCRIPT.replace(
    'restricted_globals["_getattr_"] = safer_getattr',
    'restricted_globals["_getattr_"] = getattr  # MISCONFIGURED: safer_getattr dropped',
)
assert _WORKER_SCRIPT_WEAK_GETATTR_HOOK != _WORKER_SCRIPT, (
    "Expected exactly one _getattr_ assignment line to patch in _WORKER_SCRIPT; "
    "dynamic_prober._WORKER_SCRIPT may have changed shape."
)

# --- Variant 2: getattr exposed as a plain global, _getattr_ left hardened. ---
# Single-line diff from the hardened _WORKER_SCRIPT: adds one extra global.
_WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN = _WORKER_SCRIPT.replace(
    'restricted_globals["_write_"] = full_write_guard',
    'restricted_globals["_write_"] = full_write_guard\n'
    '    restricted_globals["getattr"] = getattr  # MISCONFIGURED: dangerous builtin restored',
)
assert _WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN != _WORKER_SCRIPT, (
    "Expected exactly one _write_ assignment line to patch in _WORKER_SCRIPT; "
    "dynamic_prober._WORKER_SCRIPT may have changed shape."
)


def sandbox_exec_weak_getattr_hook(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with `_getattr_` wired to plain `getattr` instead of `safer_getattr`.

    Same isolation, timeout, and result-dict contract as
    `dynamic_prober.sandbox_exec`; see module docstring ("Variant 1") for what
    is weakened and why it is a realistic mistake, not a RestrictedPython bug.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_WEAK_GETATTR_HOOK, code, timeout=timeout, config=config, work_dir=work_dir
    )


def sandbox_exec_exposed_getattr_builtin(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with the plain `getattr` builtin restored to the sandbox globals.

    Same isolation, timeout, and result-dict contract as
    `dynamic_prober.sandbox_exec`; see module docstring ("Variant 2") for what
    is weakened and why it is a realistic mistake, not a RestrictedPython bug.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN, code, timeout=timeout, config=config, work_dir=work_dir
    )


MISCONFIGURED_VARIANTS: dict[str, Any] = {
    "weak_getattr_hook": sandbox_exec_weak_getattr_hook,
    "exposed_getattr_builtin": sandbox_exec_exposed_getattr_builtin,
}
