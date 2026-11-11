"""Mutational fuzzer: semantics-preserving obfuscations of the payload corpus.

For every payload we enumerate *mutation sites* and rewrite each one with every
obfuscation form, producing hundreds of variants.  The robustness claim is:

    for each variant, the static analyzer still reports every technique it
    reported for the original payload.

Sites
-----
* ``string``  -- a string literal (len >= 3) is replaced by an expression that
  evaluates to the same value (concat, join, bytes.decode, chr chain, f-string,
  %-format, reversed slice, replace, hex, or hoisting into a variable).
* ``attr``    -- ``x.__dunder__`` (Load) becomes ``getattr(x, <obfuscated name>)``,
  which removes the literal dunder AST node entirely -- the real evasion.

Enumeration is exhaustive (site x form); no randomness is involved, so results
are reproducible and the published number is exact.
"""

from __future__ import annotations

import ast
import copy
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from sandbox_escape_finder.payloads import PAYLOADS
from sandbox_escape_finder.static_analyzer import StaticAnalyzer

_HOIST = "_fz_hoisted"


def _c(v: object) -> ast.Constant:
    return ast.Constant(value=v)


def _call(func: ast.expr, *args: ast.expr) -> ast.Call:
    return ast.Call(func=func, args=list(args), keywords=[])


def _attr(value: ast.expr, name: str) -> ast.Attribute:
    return ast.Attribute(value=value, attr=name, ctx=ast.Load())


def _name(n: str) -> ast.Name:
    return ast.Name(id=n, ctx=ast.Load())


def _join(seq: ast.expr) -> ast.Call:
    return _call(_attr(_c(""), "join"), seq)


def _concat(parts: list[ast.expr]) -> ast.expr:
    out = parts[0]
    for p in parts[1:]:
        out = ast.BinOp(left=out, op=ast.Add(), right=p)
    return out


def _ints(s: str) -> ast.List:
    return ast.List(elts=[_c(ord(ch)) for ch in s], ctx=ast.Load())


def _cut(s: str, n: int) -> list[str]:
    k = max(1, len(s) // n)
    return [s[i : i + k] for i in range(0, len(s), k)]


def _halves(s: str) -> tuple[str, str]:
    return s[: len(s) // 2], s[len(s) // 2 :]


def _placeholder_replace(s: str) -> ast.expr:
    ph = next(ch for ch in "QXZ#~" if ch not in s)
    i = len(s) // 2
    return _call(_attr(_c(s[:i] + ph + s[i + 1 :]), "replace"), _c(ph), _c(s[i]))


def _chr_genexp(s: str) -> ast.expr:
    comp = ast.comprehension(target=ast.Name(id="_c", ctx=ast.Store()), iter=_ints(s), ifs=[], is_async=0)
    return _join(ast.GeneratorExp(elt=_call(_name("chr"), _name("_c")), generators=[comp]))


# form name -> builder(str) -> ast.expr evaluating to that str
FORMS: dict[str, Callable[[str], ast.expr]] = {
    "literal_control": lambda s: _c(s),
    "concat_2": lambda s: _concat([_c(p) for p in _halves(s)]),
    "concat_3": lambda s: _concat([_c(p) for p in _cut(s, 3)]),
    "concat_chars": lambda s: _concat([_c(ch) for ch in s]),
    "join_chars": lambda s: _join(ast.List(elts=[_c(ch) for ch in s], ctx=ast.Load())),
    "join_parts": lambda s: _join(ast.Tuple(elts=[_c(p) for p in _cut(s, 3)], ctx=ast.Load())),
    "bytes_decode": lambda s: _call(_attr(_c(s.encode()), "decode")),
    "bytes_list_decode": lambda s: _call(_attr(_call(_name("bytes"), _ints(s)), "decode")),
    "hex_decode": lambda s: _call(
        _attr(_call(_attr(_name("bytes"), "fromhex"), _c(s.encode().hex())), "decode")
    ),
    "chr_concat": lambda s: _concat([_call(_name("chr"), _c(ord(ch))) for ch in s]),
    "chr_genexp": _chr_genexp,
    "map_chr": lambda s: _join(_call(_name("map"), _name("chr"), _ints(s))),
    "reversed_slice": lambda s: ast.Subscript(value=_c(s[::-1]), slice=ast.Slice(step=_c(-1)), ctx=ast.Load()),
    "fstring": lambda s: ast.JoinedStr(
        values=[_c(_halves(s)[0]), ast.FormattedValue(value=_c(_halves(s)[1]), conversion=-1)]
    ),
    "percent_format": lambda s: ast.BinOp(
        left=_c("%s%s"), op=ast.Mod(), right=ast.Tuple(elts=[_c(p) for p in _halves(s)], ctx=ast.Load())
    ),
    "replace_char": _placeholder_replace,
    "compose_bytes_chr": lambda s: _concat(
        [
            _call(_attr(_c(_halves(s)[0].encode()), "decode")),
            _join(_call(_name("map"), _name("chr"), _ints(_halves(s)[1]))),
        ]
    ),
    "hoisted_variable": lambda s: _name(_HOIST),  # plus an assignment prepended in generate_variants
}


@dataclass(frozen=True)
class Variant:
    payload_id: str
    technique: str
    site_kind: str  # 'string' | 'attr'
    form: str
    source: str


@dataclass
class FuzzReport:
    variants: int = 0
    caught: int = 0
    missed: list[Variant] = field(default_factory=list)
    skipped_payloads: list[str] = field(default_factory=list)
    by_form: Counter = field(default_factory=Counter)
    caught_by_form: Counter = field(default_factory=Counter)
    by_kind: Counter = field(default_factory=Counter)
    caught_by_kind: Counter = field(default_factory=Counter)

    def summary(self) -> str:
        pct = 100 * self.caught / max(1, self.variants)
        return f"{self.caught}/{self.variants} variants caught ({pct:.1f}%)"


def _sites(tree: ast.AST) -> list[tuple[str, int]]:
    """(kind, index-in-ast.walk-order) for every mutable site."""
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    out = []
    for i, n in enumerate(ast.walk(tree)):
        parent = parents.get(n)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 3:
            if not isinstance(parent, (ast.JoinedStr, ast.FormattedValue, ast.Expr)):
                out.append(("string", i))
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and len(n.attr) >= 3:
            out.append(("attr", i))
    return out


def _swap(root: ast.AST, old: ast.AST, new: ast.AST) -> None:
    for parent in ast.walk(root):
        for fname, val in ast.iter_fields(parent):
            if val is old:
                setattr(parent, fname, new)
                return
            if isinstance(val, list):
                for i, item in enumerate(val):
                    if item is old:
                        val[i] = new
                        return
    raise LookupError("mutation site not found")


def generate_variants(payload: dict[str, str]) -> list[Variant]:
    """All site x form mutations of one payload, as unparsed source strings."""
    tree = ast.parse(payload["code"])
    out: list[Variant] = []
    for kind, idx in _sites(tree):
        for form, build in FORMS.items():
            mutated = copy.deepcopy(tree)
            target = list(ast.walk(mutated))[idx]
            value = target.value if kind == "string" else target.attr  # type: ignore[union-attr]
            replacement = build(value)
            if kind == "attr":
                replacement = _call(_name("getattr"), target.value, replacement)  # type: ignore[union-attr]
            _swap(mutated, target, ast.copy_location(replacement, target))
            if form == "hoisted_variable":
                assign = ast.Assign(targets=[ast.Name(id=_HOIST, ctx=ast.Store())], value=_c(value), lineno=1)
                mutated.body.insert(0, assign)  # type: ignore[attr-defined]
            src = ast.unparse(ast.fix_missing_locations(mutated))
            out.append(Variant(payload["id"], payload["technique"], kind, form, src))
    return out


def run_fuzz(
    analyzer: StaticAnalyzer | None = None,
    payloads: list[dict[str, str]] | None = None,
    reference: StaticAnalyzer | None = None,
) -> FuzzReport:
    """Mutate every payload and check each variant keeps all original techniques.

    ``reference`` (default: ``analyzer``) decides each payload's *expected* technique
    set and which payloads are fuzzable; pass the full analyzer here when scoring an
    ablated analyzer so both are measured on identical variants.
    """
    analyzer = analyzer or StaticAnalyzer()
    reference = reference or analyzer
    report = FuzzReport()
    for p in payloads if payloads is not None else PAYLOADS:
        baseline = {f["technique"] for f in reference.scan(p["code"])}
        if not baseline:
            report.skipped_payloads.append(p["id"])
            continue
        for v in generate_variants(p):
            ast.parse(v.source)  # every variant must be valid Python
            got = {f["technique"] for f in analyzer.scan(v.source)}
            report.variants += 1
            report.by_form[v.form] += 1
            report.by_kind[v.site_kind] += 1
            if baseline <= got:
                report.caught += 1
                report.caught_by_form[v.form] += 1
                report.caught_by_kind[v.site_kind] += 1
            else:
                report.missed.append(v)
    return report
