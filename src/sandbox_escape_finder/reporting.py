"""Cross-reference static findings against dynamic escape results.

This is the only module that sees both sides: static findings (from
StaticAnalyzer) and dynamic outcomes (from DynamicProber). It does no scanning
and no execution itself.

Row semantics:
    static_flagged     True if the analyzer produced at least one finding for the
                       payload, from ANY detector (not only the payload's own
                       technique).
    static_confidence  Highest confidence among that payload's findings
                       ('HIGH' > 'MEDIUM' > 'LOW'), or None if not flagged.
    dynamic_executed   The payload compiled and ran to completion in the sandbox.
    dynamic_escaped    The oracle's verdict (canary file changed or leaked).
    timing             Seconds spent executing the payload in the sandbox.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

_CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"
FALSE_NEGATIVE = "false_negative"
TRUE_NEGATIVE = "true_negative"
CATEGORIES = (TRUE_POSITIVE, FALSE_POSITIVE, FALSE_NEGATIVE, TRUE_NEGATIVE)

_CATEGORY_LABELS = {
    TRUE_POSITIVE: "True positive (flagged, escaped)",
    FALSE_POSITIVE: "False positive (flagged, did not escape)",
    FALSE_NEGATIVE: "False negative (not flagged, escaped)",
    TRUE_NEGATIVE: "True negative (not flagged, did not escape)",
}


def _confidence_of(finding: Any) -> str:
    return finding["confidence"] if isinstance(finding, Mapping) else finding.confidence


def determine_blocking_mechanism(entry: Mapping[str, Any]) -> str:
    """Determine which defense layer stopped the payload, or if it ran/escaped."""
    if entry.get("escaped") or entry.get("capability_recovered"):
        return "Escaped"
    if entry.get("executed"):
        return "Contained (safe execution)"
    exc = str(entry.get("exception") or "")
    if 'starts with "_"' in exc or "starts with '_'" in exc:
        return "Compile-time (underscore rule)"
    if "is a restricted name" in exc or "statements are not allowed" in exc:
        return "Compile-time (restricted name check)"
    if "NameError" in exc:
        return "Runtime (safe_globals stripped builtin)"
    if "NotImplementedError" in exc or "safer_getattr" in exc:
        return "Runtime guard (safer_getattr)"
    if exc:
        return f"Runtime error ({exc.split(':')[0]})"
    return "Unknown"


def build_comparison_table(
    findings_by_payload: Mapping[str, list[Any]],
    prober_report: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build one comparison row per payload in the prober report.

    Args:
        findings_by_payload: payload_id -> list of static findings (Finding
            objects or finding dicts). A payload with no findings must map to
            an empty list; a missing key raises, so an unscanned payload can
            never be silently counted as "not flagged".
        prober_report: Output of DynamicProber.run().

    Returns:
        One dict per payload, in report order, with keys payload_id, technique,
        static_flagged, static_confidence, dynamic_executed, dynamic_escaped,
        capability_recovered, blocking_mechanism, timing.
    """
    missing = [e["payload_id"] for e in prober_report if e["payload_id"] not in findings_by_payload]
    if missing:
        raise ValueError(f"No static findings entry for payload(s): {missing}")

    table: list[dict[str, Any]] = []
    for entry in prober_report:
        findings = findings_by_payload[entry["payload_id"]]
        confidence = (
            max((_confidence_of(f) for f in findings), key=_CONFIDENCE_RANK.__getitem__)
            if findings
            else None
        )
        table.append(
            {
                "payload_id": entry["payload_id"],
                "technique": entry["technique"],
                "static_flagged": bool(findings),
                "static_confidence": confidence,
                "dynamic_executed": bool(entry["executed"]),
                "dynamic_escaped": bool(entry["escaped"]),
                "capability_recovered": bool(entry.get("capability_recovered", False)),
                "blocking_mechanism": determine_blocking_mechanism(entry),
                "timing": entry["timing"],
            }
        )
    return table


def classify_row(row: Mapping[str, Any]) -> str:
    """Return the confusion-matrix category of one comparison row."""
    flagged = row["static_flagged"]
    escaped = row["dynamic_escaped"] or row.get("capability_recovered", False)
    if flagged and escaped:
        return TRUE_POSITIVE
    if flagged:
        return FALSE_POSITIVE
    if escaped:
        return FALSE_NEGATIVE
    return TRUE_NEGATIVE


def classify_table(table: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group rows into the four categories (every category key is always present)."""
    groups: dict[str, list[dict[str, Any]]] = {c: [] for c in CATEGORIES}
    for row in table:
        groups[classify_row(row)].append(dict(row))
    return groups


def to_markdown_table(table: list[Mapping[str, Any]]) -> str:
    """Render the comparison table as a Markdown table."""
    header = (
        "| payload_id | technique | static_flagged | static_confidence "
        "| dynamic_executed | dynamic_escaped | capability_recovered | blocking_mechanism | timing (s) | category |"
    )
    sep = "|---|---|---|---|---|---|---|---|---|---|"
    lines = [header, sep]
    for r in table:
        lines.append(
            f"| {r['payload_id']} | {r['technique']} | {r['static_flagged']} "
            f"| {r['static_confidence'] or '-'} | {r['dynamic_executed']} "
            f"| {r['dynamic_escaped']} | {r.get('capability_recovered', False)} "
            f"| {r.get('blocking_mechanism', '-')} "
            f"| {r['timing']} | {_CATEGORY_LABELS[classify_row(r)].split(' (')[0]} |"
        )
    return "\n".join(lines)


def to_markdown_summary(table: list[Mapping[str, Any]]) -> str:
    """Render overall and per-technique confusion counts as Markdown.

    Counts are reported as-is, including zeros.
    """
    groups = classify_table(table)
    out = ["| Category | Definition | Count | Payloads |", "|---|---|---|---|"]
    for cat in CATEGORIES:
        label, definition = _CATEGORY_LABELS[cat].split(" (")
        ids = ", ".join(r["payload_id"] for r in groups[cat]) or "none"
        out.append(f"| {label} | {definition.rstrip(')')} | {len(groups[cat])} | {ids} |")

    per_tech: dict[str, dict[str, int]] = defaultdict(lambda: {c: 0 for c in CATEGORIES})
    for r in table:
        per_tech[r["technique"]][classify_row(r)] += 1
    out += [
        "",
        "| technique | payloads | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|",
    ]
    for tech in sorted(per_tech):
        c = per_tech[tech]
        total = sum(c.values())
        out.append(
            f"| {tech} | {total} | {c[TRUE_POSITIVE]} | {c[FALSE_POSITIVE]} "
            f"| {c[FALSE_NEGATIVE]} | {c[TRUE_NEGATIVE]} |"
        )
    return "\n".join(out)
