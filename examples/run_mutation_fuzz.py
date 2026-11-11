"""Experiment 4: adversarial robustness of the constant-folding static analyzer.

Mutates every payload (string-literal rewriting and attribute -> getattr
conversion, 18 obfuscation forms) and reports how many variants the analyzer
still flags, with and without the constant-folding pass.
"""

from __future__ import annotations

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.mutation_fuzzer import FORMS, run_fuzz
from sandbox_escape_finder.static_analyzer import StaticAnalyzer


def main() -> None:
    folded = run_fuzz(StaticAnalyzer())
    literal = run_fuzz(StaticAnalyzer(SandboxConfig(constant_folding=False)), reference=StaticAnalyzer())

    print(f"Payloads skipped (never flagged even unmutated): {folded.skipped_payloads or 'none'}")
    print()
    print(f"With constant folding : {folded.summary()}")
    print(f"Literal-only (ablated): {literal.summary()}")
    print()
    print("| Obfuscation form | Variants | Folding | Literal-only |")
    print("|---|---|---|---|")
    for form in FORMS:
        print(
            f"| {form} | {folded.by_form[form]} | {folded.caught_by_form[form]} "
            f"| {literal.caught_by_form[form]} |"
        )
    print()
    for kind in ("string", "attr"):
        print(f"{kind:7s}: folding {folded.caught_by_kind[kind]}/{folded.by_kind[kind]}, "
              f"literal-only {literal.caught_by_kind[kind]}/{literal.by_kind[kind]}")
    if folded.missed:
        print("\nMissed by folding analyzer:")
        for v in folded.missed[:20]:
            print(f"  {v.payload_id} [{v.site_kind}/{v.form}]: {v.source[:100]!r}")


if __name__ == "__main__":
    main()
