"""Adversarial robustness: the folding analyzer must catch every mutated payload."""

from __future__ import annotations

import ast

from sandbox_escape_finder.config import SandboxConfig
from sandbox_escape_finder.mutation_fuzzer import FORMS, generate_variants, run_fuzz
from sandbox_escape_finder.payloads import PAYLOADS
from sandbox_escape_finder.static_analyzer import StaticAnalyzer


def test_variants_are_valid_python_and_nontrivial() -> None:
    total = 0
    for p in PAYLOADS:
        for v in generate_variants(p):
            ast.parse(v.source)
            total += 1
    assert total >= 500


def test_every_form_value_preserving() -> None:
    """Each form evaluates (via real Python) to the original string."""
    target = "__subclasses__"
    for name, build in FORMS.items():
        if name == "hoisted_variable":
            continue
        expr = ast.fix_missing_locations(ast.Expression(body=build(target)))
        assert eval(compile(expr, "<form>", "eval")) == target, name


def test_all_variants_caught() -> None:
    report = run_fuzz()
    assert report.variants > 0
    assert report.caught == report.variants, [(m.payload_id, m.site_kind, m.form) for m in report.missed[:10]]


def test_folding_is_load_bearing() -> None:
    full = run_fuzz()
    ablated = run_fuzz(StaticAnalyzer(SandboxConfig(constant_folding=False)), reference=StaticAnalyzer())
    assert ablated.variants == full.variants
    assert ablated.caught < full.caught
