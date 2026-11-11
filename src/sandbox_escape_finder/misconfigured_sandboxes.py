"""Misconfigured and ablated RestrictedPython sandboxes (Experiments 1-2 support code).

`dynamic_prober.sandbox_exec` wires RestrictedPython 8.5 exactly as its own
documentation describes (`compile_restricted` + the full `safe_globals` guard
set). The 20-payload corpus (`payloads.py`) produces zero escapes against it;
see `results/experiment1.md`.

This module holds the variants used to locate the boundary of that result.
Every variant is a worker script derived from the hardened `_WORKER_SCRIPT`
and run through `dynamic_prober._run_worker_script` (same subprocess isolation,
disposable work dir, and timeout). The RestrictedPython files on disk are never
modified. Variants 1, 2 and ablations C and D change only the globals the
integrator passes to `exec()`. Ablations A and B additionally monkey-patch
`RestrictedPython.transformer` / `RestrictedPython.Guards` in the worker
process's memory.

Realistic integration mistakes (results/experiment2.md)
-------------------------------------------------------
Variant 1 `sandbox_exec_weak_getattr_hook`: `_getattr_` = plain `getattr`
    instead of `Guards.safer_getattr`. Reopens `str.format` / `format_map`
    attribute traversal, which can only stringify an attribute chain
    (information disclosure); the canary oracle does not score that.
Variant 2 `sandbox_exec_exposed_getattr_builtin`: the `getattr` builtin is added
    to the sandbox globals. Payloads that build a dunder name at runtime
    (`getattr(int, '__base__')`) now run and can reach the real `open()`.

Defense-layer ablation (results/ablation.md)
--------------------------------------------
Four variants, one per layer, each run against the same 20 payloads:

  A  `sandbox_exec_layer_a_disabled`: `check_name` and `visit_Attribute` stop
     rejecting `_`-prefixed names (transformer.py), AND `_getattr_` is replaced
     by a copy of `safer_getattr` without its `startswith('_')` check
     (Guards.py), because with only the compile-time check removed the runtime
     check blocks every payload anyway.
  B  `sandbox_exec_layer_b_disabled`: `INSPECT_ATTRIBUTES` is set to an empty
     set in both `transformer` (compile time) and `Guards` (read by
     `safer_getattr` at run time).
  C  `sandbox_exec_layer_c_disabled`: `__builtins__` is the real `builtins`
     module instead of `safe_globals`' stripped dict.
  D  `sandbox_exec_layer_d_disabled`: `_getattr_` = plain `getattr`; identical
     to Variant 1. This removes every check inside `safer_getattr` (format,
     `string.Formatter`, `INSPECT_ATTRIBUTES`, underscore), not only the
     format guard.

The layers are therefore not orthogonal: A and B each remove a compile-time
check plus its run-time twin in `safer_getattr`, and D removes all run-time
twins at once. A payload reported as load-bearing "only on A" means no single
other ablation lets it escape; it does not mean the run-time twin is
irrelevant. An ablation counts a payload as escaped only when the canary oracle
or `capability_recovered` fires, so information-disclosure-only leaks (the
Variant 1 / D gadget) count as safe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.dynamic_prober import _WORKER_SCRIPT, _run_worker_script

# ---------------------------------------------------------------------------
# Variant 1 -- weak `_getattr_` hook  (Layer D disabled)
# Single-line diff from the hardened _WORKER_SCRIPT: drops the safer_getattr
# import/usage and assigns the builtin getattr directly.
# ---------------------------------------------------------------------------
_WORKER_SCRIPT_WEAK_GETATTR_HOOK = _WORKER_SCRIPT.replace(
    'restricted_globals["_getattr_"] = safer_getattr',
    'restricted_globals["_getattr_"] = getattr  # MISCONFIGURED: safer_getattr dropped',
)
assert _WORKER_SCRIPT_WEAK_GETATTR_HOOK != _WORKER_SCRIPT, (
    "Expected exactly one _getattr_ assignment line to patch in _WORKER_SCRIPT; "
    "dynamic_prober._WORKER_SCRIPT may have changed shape."
)

# ---------------------------------------------------------------------------
# Variant 2 -- getattr exposed as a plain global  (extra dangerous builtin)
# Single-line diff from the hardened _WORKER_SCRIPT: adds one extra global.
# ---------------------------------------------------------------------------
_WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN = _WORKER_SCRIPT.replace(
    'restricted_globals["_write_"] = full_write_guard',
    'restricted_globals["_write_"] = full_write_guard\n'
    '    restricted_globals["getattr"] = getattr  # MISCONFIGURED: dangerous builtin restored',
)
assert _WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN != _WORKER_SCRIPT, (
    "Expected exactly one _write_ assignment line to patch in _WORKER_SCRIPT; "
    "dynamic_prober._WORKER_SCRIPT may have changed shape."
)

# ---------------------------------------------------------------------------
# Ablation Layer A: compile-time underscore rule disabled
#
# Monkey-patches `RestrictingNodeTransformer.check_name` to skip the
# startswith('_') guard, and `visit_Attribute` to skip its own `startswith('_')`
# check on node.attr -- both while keeping INSPECT_ATTRIBUTES enforcement and
# the __roles__ suffix rule intact.  Also provides a matching `_getattr_` hook
# that skips the underscore runtime check in safer_getattr so the payload
# actually runs rather than failing at the safer_getattr runtime guard.
#
# This is a realistic mistake: an integrator subclasses or patches
# RestrictingNodeTransformer to relax "overly aggressive" naming restrictions
# (a reported pain point in several projects' issue trackers), without
# understanding that the underscore rule is the primary gate for the entire
# __class__/__bases__/__subclasses__ chain.
# ---------------------------------------------------------------------------
_LAYER_A_PATCH = '''\
import RestrictedPython.transformer as _rp_T
import RestrictedPython.Guards as _rp_G
import ast as _ast_mod
from RestrictedPython.transformer import copy_locations as _copy_locs

def _check_name_no_underscore(self, node, name, allow_magic_methods=False):
    """check_name with the leading-underscore guard removed (Layer A ablation)."""
    if name is None:
        return
    if name.endswith('__roles__'):
        self.error(node, '"{name}" is an invalid variable name because it ends with "__roles__".'.format(name=name))
    elif name in _rp_T.FORBIDDEN_FUNC_NAMES:
        self.error(node, '"{name}" is a reserved name.'.format(name=name))

_orig_va = _rp_T.RestrictingNodeTransformer.visit_Attribute

def _visit_Attribute_no_underscore(self, node):
    """visit_Attribute with the leading-underscore attr guard removed (Layer A ablation)."""
    if node.attr.endswith('__roles__'):
        self.error(node, '"{name}" is an invalid attribute name because it ends with "__roles__".'.format(name=node.attr))
    if node.attr in _rp_T.INSPECT_ATTRIBUTES:
        self.error(node, '"{name}" is a restricted name, that is forbidden to access in RestrictedPython.'.format(name=node.attr))
    if isinstance(node.ctx, _ast_mod.Load):
        node = self.node_contents_visit(node)
        new_node = _ast_mod.Call(
            func=_ast_mod.Name('_getattr_', _ast_mod.Load()),
            args=[node.value, _ast_mod.Constant(node.attr)],
            keywords=[])
        _copy_locs(new_node, node)
        return new_node
    elif isinstance(node.ctx, (_ast_mod.Store, _ast_mod.Del)):
        node = self.node_contents_visit(node)
        new_value = _ast_mod.Call(
            func=_ast_mod.Name('_write_', _ast_mod.Load()),
            args=[node.value],
            keywords=[])
        _copy_locs(new_value, node.value)
        node.value = new_value
        return node
    return _orig_va(self, node)

_rp_T.RestrictingNodeTransformer.check_name = _check_name_no_underscore
_rp_T.RestrictingNodeTransformer.visit_Attribute = _visit_Attribute_no_underscore

def _safer_getattr_no_underscore(object, name, default=None, getattr=getattr):
    """safer_getattr with the leading-underscore check removed (Layer A ablation).

    The format/format_map guard, INSPECT_ATTRIBUTES guard, and __roles__ guard
    remain intact -- only the underscore name check is removed, mirroring what
    the compile-time patch allows through.
    """
    import string as _string
    if type(name) is not str:
        raise TypeError('type(name) must be str')
    if name in ('format', 'format_map') and (
            isinstance(object, str) or
            (isinstance(object, type) and issubclass(object, str))):
        raise NotImplementedError('Using the format*() methods of `str` is not safe')
    if name in _rp_G.INSPECT_ATTRIBUTES:
        raise AttributeError(
            '"{name}" is a restricted name, that is forbidden to access in RestrictedPython.'.format(name=name))
    return getattr(object, name) if default is None else getattr(object, name, default)
'''

_WORKER_SCRIPT_LAYER_A_DISABLED = _WORKER_SCRIPT.replace(
    "import RestrictedPython\n",
    "import RestrictedPython\n" + _LAYER_A_PATCH + "\n",
).replace(
    'restricted_globals["_getattr_"] = safer_getattr',
    'restricted_globals["_getattr_"] = _safer_getattr_no_underscore'
    '  # ABLATION A: underscore guard removed from compile-time and runtime',
)
assert _WORKER_SCRIPT_LAYER_A_DISABLED != _WORKER_SCRIPT, (
    "Layer A patch did not modify _WORKER_SCRIPT; check anchor strings."
)

# ---------------------------------------------------------------------------
# Ablation Layer B: compile-time restricted-names (INSPECT_ATTRIBUTES) disabled
#
# Sets `RestrictedPython.transformer.INSPECT_ATTRIBUTES` and
# `RestrictedPython.Guards.INSPECT_ATTRIBUTES` to `set()` before compilation,
# removing the specific block on frame introspection attributes like
# `gi_frame`, `f_globals`, `f_back`, `cr_frame`, `f_builtins`, etc.
#
# Realistic mistake: an integrator who needs to debug generator or async code
# inside the sandbox adds a one-liner `T.INSPECT_ATTRIBUTES = set()` to
# "unblock" those attributes, not realising they are the second gate that
# stops frame-walk escapes that the underscore rule alone cannot prevent
# (e.g. `gi_frame`, `f_globals`, `f_back` -- none start with `_`).
# ---------------------------------------------------------------------------
_LAYER_B_PATCH = '''\
import RestrictedPython.transformer as _rp_T
import RestrictedPython.Guards as _rp_G
_rp_T.INSPECT_ATTRIBUTES = set()   # ABLATION B: restricted-names enforcement removed
_rp_G.INSPECT_ATTRIBUTES = set()   # patch runtime guard to match
'''

_WORKER_SCRIPT_LAYER_B_DISABLED = _WORKER_SCRIPT.replace(
    "import RestrictedPython\n",
    "import RestrictedPython\n" + _LAYER_B_PATCH + "\n",
)
assert _WORKER_SCRIPT_LAYER_B_DISABLED != _WORKER_SCRIPT, (
    "Layer B patch did not modify _WORKER_SCRIPT; check anchor strings."
)

# ---------------------------------------------------------------------------
# Ablation Layer C: safe_globals builtins disabled (full builtins supplied)
#
# Replaces the restricted `__builtins__` dict from `safe_globals` with the
# real `builtins` module, giving sandboxed code access to `getattr`, `open`,
# `eval`, `exec`, `__import__`, and everything else in the standard library.
#
# Realistic mistake: an integrator encounters a NameError for a builtin they
# expect to work (e.g. `getattr`, `len`, `print`) and "fixes" it by swapping
# in the real builtins module or dict.  This is the most catastrophic of the
# four mistakes: it nullifies safe_globals entirely and re-enables every
# runtime path that depends on a named builtin.
# ---------------------------------------------------------------------------
_WORKER_SCRIPT_LAYER_C_DISABLED = _WORKER_SCRIPT.replace(
    'restricted_globals = safe_globals.copy()',
    'restricted_globals = safe_globals.copy()\n'
    '    restricted_globals["__builtins__"] = builtins'
    '  # ABLATION C: full builtins supplied -- safe_globals stripped set bypassed',
)
assert _WORKER_SCRIPT_LAYER_C_DISABLED != _WORKER_SCRIPT, (
    "Layer C patch did not modify _WORKER_SCRIPT; check anchor strings."
)

# ---------------------------------------------------------------------------
# Ablation Layer D: safer_getattr runtime guard disabled
# (identical to Variant 1 above; kept as a named constant for the ablation API)
# ---------------------------------------------------------------------------
_WORKER_SCRIPT_LAYER_D_DISABLED = _WORKER_SCRIPT_WEAK_GETATTR_HOOK


# ---------------------------------------------------------------------------
# Public exec functions
# ---------------------------------------------------------------------------

def sandbox_exec_weak_getattr_hook(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with `_getattr_` wired to plain `getattr` instead of `safer_getattr`.

    Same isolation, timeout, and result-dict contract as
    `dynamic_prober.sandbox_exec`; see module docstring (\"Variant 1\") for what
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
    `dynamic_prober.sandbox_exec`; see module docstring (\"Variant 2\") for what
    is weakened and why it is a realistic mistake, not a RestrictedPython bug.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_EXPOSED_GETATTR_BUILTIN, code, timeout=timeout, config=config, work_dir=work_dir
    )


def sandbox_exec_layer_a_disabled(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with Layer A (compile-time underscore rule) disabled.

    Both `check_name` and `visit_Attribute`'s leading-underscore guards are
    monkey-patched away before compilation, and the matching runtime hook drops
    the underscore check from `safer_getattr`.  All other layers (B, C, D) are
    left at their hardened defaults.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_LAYER_A_DISABLED, code, timeout=timeout, config=config, work_dir=work_dir
    )


def sandbox_exec_layer_b_disabled(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with Layer B (compile-time restricted-names / INSPECT_ATTRIBUTES) disabled.

    `RestrictedPython.transformer.INSPECT_ATTRIBUTES` and
    `RestrictedPython.Guards.INSPECT_ATTRIBUTES` are cleared to `set()` before
    compilation.  All other layers (A, C, D) are at their hardened defaults.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_LAYER_B_DISABLED, code, timeout=timeout, config=config, work_dir=work_dir
    )


def sandbox_exec_layer_c_disabled(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with Layer C (safe_globals builtins) disabled.

    The restricted `__builtins__` dict from `safe_globals` is replaced with the
    real `builtins` module, giving sandboxed code access to `getattr`, `open`,
    `eval`, `exec`, and all other standard builtins.  Layers A, B, D remain
    hardened.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_LAYER_C_DISABLED, code, timeout=timeout, config=config, work_dir=work_dir
    )


def sandbox_exec_layer_d_disabled(
    code: str,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
    work_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Run `code` with Layer D (safer_getattr runtime guard) disabled.

    `_getattr_` is wired to the plain builtin `getattr` instead of
    `safer_getattr`, removing the format/format_map guard and the underscore
    runtime check.  Layers A, B, C remain hardened.  This is identical to
    `sandbox_exec_weak_getattr_hook` and is re-exported here for the ablation
    matrix API symmetry.
    """
    return _run_worker_script(
        _WORKER_SCRIPT_LAYER_D_DISABLED, code, timeout=timeout, config=config, work_dir=work_dir
    )


MISCONFIGURED_VARIANTS: dict[str, Any] = {
    "weak_getattr_hook": sandbox_exec_weak_getattr_hook,
    "exposed_getattr_builtin": sandbox_exec_exposed_getattr_builtin,
}

#: All four ablation-layer exec functions keyed by short layer name.
ABLATION_LAYER_VARIANTS: dict[str, Any] = {
    "layer_a_disabled": sandbox_exec_layer_a_disabled,
    "layer_b_disabled": sandbox_exec_layer_b_disabled,
    "layer_c_disabled": sandbox_exec_layer_c_disabled,
    "layer_d_disabled": sandbox_exec_layer_d_disabled,
}
