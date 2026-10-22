"""Unit tests for the static-vs-dynamic comparison layer."""

import pytest

from sandbox_escape_finder.reporting import (
    FALSE_NEGATIVE,
    FALSE_POSITIVE,
    TRUE_NEGATIVE,
    TRUE_POSITIVE,
    build_comparison_table,
    classify_row,
    classify_table,
    to_markdown_summary,
    to_markdown_table,
)
from sandbox_escape_finder.static_analyzer import Finding


def _entry(pid: str, technique: str, executed: bool, escaped: bool) -> dict:
    return {
        "payload_id": pid,
        "technique": technique,
        "executed": executed,
        "escaped": escaped,
        "timing": 0.25,
    }


def _sample_table() -> list[dict]:
    report = [
        _entry("tp", "globals_access", True, True),
        _entry("fp", "globals_access", False, False),
        _entry("fn", "frame_introspection", True, True),
        _entry("tn", "frame_introspection", True, False),
    ]
    findings = {
        # mixed Finding objects and dicts; the highest confidence must win
        "tp": [Finding("globals_access", "r", (1, 0), "MEDIUM"), {"confidence": "HIGH"}],
        "fp": [Finding("globals_access", "r", (1, 0), "LOW")],
        "fn": [],
        "tn": [],
    }
    return build_comparison_table(findings, report)


def test_rows_have_required_fields_and_confidence() -> None:
    table = _sample_table()
    assert set(table[0]) == {
        "payload_id",
        "technique",
        "static_flagged",
        "static_confidence",
        "dynamic_executed",
        "dynamic_escaped",
        "capability_recovered",
        "blocking_mechanism",
        "timing",
    }
    assert [r["static_confidence"] for r in table] == ["HIGH", "LOW", None, None]
    assert [r["static_flagged"] for r in table] == [True, True, False, False]
    assert table[1]["dynamic_executed"] is False


def test_determine_blocking_mechanism_layers() -> None:
    from sandbox_escape_finder.reporting import determine_blocking_mechanism

    assert determine_blocking_mechanism({"escaped": True}) == "Escaped"
    assert determine_blocking_mechanism({"capability_recovered": True}) == "Escaped"
    assert determine_blocking_mechanism({"executed": True}) == "Contained (safe execution)"
    assert (
        determine_blocking_mechanism({"exception": 'SyntaxError: Line 1: "__class__" is an invalid attribute name because it starts with "_".'})
        == "Compile-time (underscore rule)"
    )
    assert (
        determine_blocking_mechanism({"exception": 'SyntaxError: Line 4: "f_back" is a restricted name, that is forbidden to access in RestrictedPython.'})
        == "Compile-time (restricted name check)"
    )
    assert (
        determine_blocking_mechanism({"exception": "NameError: name 'getattr' is not defined"})
        == "Runtime (safe_globals stripped builtin)"
    )
    assert (
        determine_blocking_mechanism({"exception": "NotImplementedError: Using the format*() methods of `str` is not safe"})
        == "Runtime guard (safer_getattr)"
    )


def test_classification_covers_all_four_categories() -> None:
    table = _sample_table()
    assert [classify_row(r) for r in table] == [
        TRUE_POSITIVE,
        FALSE_POSITIVE,
        FALSE_NEGATIVE,
        TRUE_NEGATIVE,
    ]
    groups = classify_table(table)
    assert {k: [r["payload_id"] for r in v] for k, v in groups.items()} == {
        TRUE_POSITIVE: ["tp"],
        FALSE_POSITIVE: ["fp"],
        FALSE_NEGATIVE: ["fn"],
        TRUE_NEGATIVE: ["tn"],
    }


def test_missing_findings_entry_raises_instead_of_counting_as_unflagged() -> None:
    with pytest.raises(ValueError, match="ghost"):
        build_comparison_table({}, [_entry("ghost", "globals_access", True, False)])


def test_empty_category_is_reported_plainly_as_zero() -> None:
    table = build_comparison_table(
        {"a": [Finding("globals_access", "r", (1, 0), "HIGH")]},
        [_entry("a", "globals_access", True, False)],
    )
    summary = to_markdown_summary(table)
    assert "| True positive | flagged, escaped | 0 | none |" in summary
    assert "| False negative | not flagged, escaped | 0 | none |" in summary
    assert "| globals_access | 1 | 0 | 1 | 0 | 0 |" in summary


def test_markdown_table_shape() -> None:
    md = to_markdown_table(_sample_table())
    lines = md.splitlines()
    assert len(lines) == 2 + 4
    assert lines[0].count("|") == lines[2].count("|")
    assert "| fn | frame_introspection | False | - | True | True | False | Escaped | 0.25 | False negative |" in md
