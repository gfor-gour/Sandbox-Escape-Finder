"""Tests for constant folding / propagation and the soundness of its forgetting rules."""

from __future__ import annotations

import pytest

from sandbox_escape_finder.static_analyzer import StaticAnalyzer


def techniques(code: str) -> set[str]:
    return {f["technique"] for f in StaticAnalyzer().scan(code)}


@pytest.mark.parametrize(
    "code",
    [
        "getattr(int, '__sub' + 'classes__')",
        "n = '__sub' + 'classes__'\ngetattr(int, n)",
        "x = 'sub'\ngetattr(int, f'__{x}classes__')",
        "getattr(int, ''.join(['__sub', 'classes__']))",
        "getattr(int, b'__subclasses__'.decode())",
        "getattr(int, ''.join(chr(c) for c in [95,95,115,117,98,99,108,97,115,115,101,115,95,95]))",
        "getattr(int, '__sbuclasses__'.replace('bu', 'ub'))",
        "getattr(int, '__sessalcbus__'[::-1])",
        "getattr(int, '%s%s' % ('__sub', 'classes__'))",
        "a, b = '__sub', 'classes__'\ngetattr(int, a + b)",
        "n = '__sub'\nn += 'classes__'\ngetattr(int, n)",
        "p = ['__sub']\np = p + ['classes__']\ngetattr(int, ''.join(p))",
        "getattr(int, bytes.fromhex('5f5f737562636c61737365735f5f').decode())",
        "if cond:\n    n = '__subclasses__'\nelse:\n    n = '__subclasses__'\ngetattr(int, n)",
        "def f():\n    n = '__sub' + 'classes__'\n    return getattr(int, n)",
        "('{0.__cla' + 'ss__}').format(1)",
        "t = '{0.__cl'\nt += 'ass__}'\nt.format(1)",
    ],
)
def test_folds_to_high_confidence(code: str) -> None:
    findings = StaticAnalyzer().scan(code)
    assert findings and all(f["confidence"] == "HIGH" for f in findings), findings


@pytest.mark.parametrize(
    "code",
    [
        # reassigned to benign before use
        "n = '__subclasses__'\nn = 'name'\ngetattr(int, n)",
        # mutated list must not keep stale value
        "p = ['__subclasses__']\np.append('x')\ngetattr(int, ''.join(p))",
        # loop-carried value is unknown
        "n = '__subclasses__'\nfor n in names:\n    pass\ngetattr(int, n)",
        # branches disagree -> unknown
        "if c:\n    n = '__subclasses__'\nelse:\n    n = 'x'\ngetattr(int, n)",
        # parameter shadows module constant
        "n = '__subclasses__'\ndef f(n):\n    return getattr(int, n)",
        # comprehension variable shadows
        "n = '__subclasses__'\n[getattr(int, n) for n in names]",
        # global rebinding in a function invalidates
        "n = '__subclasses__'\ndef g():\n    global n\n    n = 'x'\ng()\ngetattr(int, n)",
    ],
)
def test_forgets_when_not_sound(code: str) -> None:
    assert "subclasses_traversal" not in techniques(code)


def test_huge_repetition_is_not_folded() -> None:
    assert techniques("getattr(int, 'a' * 10**9)") == set()


def test_benign_dynamic_getattr_not_flagged() -> None:
    assert StaticAnalyzer().scan("getattr(user, 'user' + 'name')") == []


def test_input_tree_not_mutated() -> None:
    import ast

    from sandbox_escape_finder.constant_folding import fold_constants

    tree = ast.parse("getattr(int, '__sub' + 'classes__')")
    before = ast.dump(tree)
    fold_constants(tree)
    assert ast.dump(tree) == before


def test_shadowed_builtin_is_not_folded():
    from sandbox_escape_finder.constant_folding import fold_constants
    import ast
    src = "def chr(x): return 'Z'\ny = chr(65)\n"
    out = ast.unparse(fold_constants(ast.parse(src)))
    assert "chr(65)" in out and "'A'" not in out


def test_huge_format_width_is_not_evaluated():
    from sandbox_escape_finder import StaticAnalyzer
    assert StaticAnalyzer().scan("getattr(x, '%1000000000s' % 'a')") == []


def test_deeply_nested_source_does_not_crash_scan():
    from sandbox_escape_finder import StaticAnalyzer
    src = "x = " + "+".join(["y"] * 1500) + "\nx.__subclasses__()\n"
    assert StaticAnalyzer().scan(src)
