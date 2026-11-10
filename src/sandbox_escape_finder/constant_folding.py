"""Forward abstract interpretation (constant folding + propagation) over Python ASTs.

Purpose
-------
The literal detectors in ``static_analyzer`` match nodes such as
``ast.Attribute(attr='__subclasses__')`` or ``getattr(x, <Constant>)``.  An
attacker defeats them by *computing* the dunder name::

    name = '__sub' + 'classes__'
    getattr(int.__base__, name)()

This module closes that gap without adding a single new detector.  It rewrites
the tree so that every sub-expression whose value is statically determinable
as a ``str`` becomes an ``ast.Constant``; the unchanged literal detectors then
fire at HIGH confidence.  Anything that cannot be resolved stays untouched
(and is left to the optional LOW-confidence heuristic).

Abstract domain
---------------
``env : Name -> value`` where *value* is a concrete Python ``str | bytes | int
| list | tuple`` (a constant) and absence from ``env`` means UNKNOWN.  The
evaluator folds:

* ``+``, ``*``, ``%`` on constants, slicing / indexing (``s[::-1]``)
* f-strings whose parts are all known (with conversions / format specs)
* ``''.join(...)``, ``.decode()``, ``.encode()``, ``.replace()``,
  ``.split()``, ``.lower()``/``.upper()``/``.strip()``, ``bytes.fromhex``
* ``chr``, ``ord``, ``str``, ``bytes``, ``list``, ``tuple``, ``reversed``,
  ``map(chr, ...)``, ``range``
* list / generator comprehensions over constant iterables

Soundness choices (all err toward *forgetting* a value, never inventing one)
---------------------------------------------------------------------------
* ``if``: both branches analysed on copies; only bindings that agree survive.
* ``for`` / ``while`` / ``try`` / ``match``: every name assigned anywhere in the
  statement is forgotten *before* the body is analysed (loop-carried values).
* function / class bodies see a copy of the outer env minus parameters; names
  rebound via ``global`` / ``nonlocal`` are forgotten afterwards.
* mutating method calls (``parts.append(...)``), subscript / attribute stores
  and ``del`` forget the receiver.
* Results larger than ``_MAX_LEN`` are not folded (guards ``'a' * 10**9``).

Known limitation: aliasing through function calls (``f(parts)`` mutating a
list) is not tracked.  A missed fold only means a missed HIGH finding; the
LOW heuristic remains as the fallback.
"""

from __future__ import annotations

import ast
import copy
from typing import Any

_MAX_LEN = 100_000
_MAX_ITEMS = 10_000


class _Unknown:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNKNOWN"


UNKNOWN: Any = _Unknown()

_MUTATORS = {
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
    "update", "add", "discard", "setdefault", "popitem", "__setitem__", "__iadd__",
}
_SEQ = (list, tuple)
_STR_METHODS_NOARG = {"lower", "upper", "strip", "lstrip", "rstrip", "title", "swapcase", "casefold", "capitalize"}


def _too_big(v: Any) -> bool:
    return isinstance(v, (str, bytes, list, tuple)) and len(v) > _MAX_LEN


def _is_const(v: Any) -> bool:
    return v is not UNKNOWN


# NOTE: str.format is deliberately NOT folded: folding the call would erase the
# template that detect_format_string_attribute_access needs to inspect.


def evaluate(node: ast.AST | None, env: dict[str, Any]) -> Any:
    """Abstractly evaluate ``node`` under ``env``; return a constant or UNKNOWN."""
    try:
        v = _eval(node, env)
    except Exception:  # any runtime failure of the *folded* op => unknown
        return UNKNOWN
    return UNKNOWN if _too_big(v) else v


def _eval_all(nodes: list[ast.expr], env: dict[str, Any]) -> list[Any] | None:
    out = []
    for n in nodes:
        if isinstance(n, ast.Starred):
            return None
        v = _eval(n, env)
        if v is UNKNOWN:
            return None
        out.append(v)
    return out


def _iterable(v: Any) -> list[Any] | None:
    if isinstance(v, (str, bytes)):
        return list(v)  # bytes -> ints, str -> chars
    if isinstance(v, _SEQ):
        return list(v)
    return None


def _eval(node: ast.AST | None, env: dict[str, Any]) -> Any:  # noqa: C901 - one dispatch table
    if node is None:
        return UNKNOWN
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, (str, bytes, int)) else UNKNOWN
    if isinstance(node, ast.Name):
        return env.get(node.id, UNKNOWN) if isinstance(node.ctx, ast.Load) else UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple)):
        items = _eval_all(node.elts, env)
        if items is None:
            return UNKNOWN
        return items if isinstance(node, ast.List) else tuple(items)
    if isinstance(node, ast.BinOp):
        return _eval_binop(node, env)
    if isinstance(node, ast.UnaryOp):
        v = _eval(node.operand, env)
        if type(v) is not int:
            return UNKNOWN
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return v
        if isinstance(node.op, ast.Invert):
            return ~v
        return UNKNOWN
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                v = _eval(part.value, env)
                if v is UNKNOWN:
                    return UNKNOWN
                if part.conversion == 115:
                    v = str(v)
                elif part.conversion == 114:
                    v = repr(v)
                elif part.conversion == 97:
                    v = ascii(v)
                spec = ""
                if part.format_spec is not None:
                    spec = _eval(part.format_spec, env)
                    if not isinstance(spec, str):
                        return UNKNOWN
                parts.append(format(v, spec))
            else:
                return UNKNOWN
        return "".join(parts)
    if isinstance(node, ast.Subscript):
        base = _eval(node.value, env)
        if base is UNKNOWN or not isinstance(base, (str, bytes, list, tuple)):
            return UNKNOWN
        if isinstance(node.slice, ast.Slice):
            bounds = []
            for b in (node.slice.lower, node.slice.upper, node.slice.step):
                bv = None if b is None else _eval(b, env)
                if bv is UNKNOWN or not (bv is None or isinstance(bv, int)):
                    return UNKNOWN
                bounds.append(bv)
            return base[slice(*bounds)]
        idx = _eval(node.slice, env)
        return base[idx] if isinstance(idx, int) else UNKNOWN
    if isinstance(node, ast.IfExp):
        t = _eval(node.test, env)
        if t is UNKNOWN or not isinstance(t, (int, str, bytes, list, tuple)):
            return UNKNOWN
        return _eval(node.body if t else node.orelse, env)
    if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
        return _eval_comp(node, env)
    if isinstance(node, ast.Call):
        return _eval_call(node, env)
    return UNKNOWN


def _eval_binop(node: ast.BinOp, env: dict[str, Any]) -> Any:
    left, right = _eval(node.left, env), _eval(node.right, env)
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    op = node.op
    if isinstance(op, ast.Add):
        same = (
            (isinstance(left, str) and isinstance(right, str))
            or (isinstance(left, bytes) and isinstance(right, bytes))
            or (isinstance(left, list) and isinstance(right, list))
            or (isinstance(left, tuple) and isinstance(right, tuple))
            or (type(left) is int and type(right) is int)
        )
        return left + right if same else UNKNOWN
    if isinstance(op, ast.Mult):
        seq, n = (left, right) if isinstance(right, int) else (right, left)
        if isinstance(seq, (str, bytes, list, tuple)) and isinstance(n, int):
            if n > 0 and len(seq) * n > _MAX_LEN:
                return UNKNOWN
            return seq * n
        return UNKNOWN
    if isinstance(op, ast.Mod) and isinstance(left, str):
        return left % right
    return UNKNOWN


def _eval_comp(node: ast.ListComp | ast.GeneratorExp, env: dict[str, Any]) -> Any:
    if len(node.generators) != 1:
        return UNKNOWN
    gen = node.generators[0]
    if gen.is_async or not isinstance(gen.target, ast.Name):
        return UNKNOWN
    items = _iterable(_eval(gen.iter, env))
    if items is None or len(items) > _MAX_ITEMS:
        return UNKNOWN
    out = []
    for item in items:
        local = dict(env)
        local[gen.target.id] = item
        keep = True
        for cond in gen.ifs:
            c = _eval(cond, local)
            if c is UNKNOWN:
                return UNKNOWN
            keep = keep and bool(c)
        if keep:
            v = _eval(node.elt, local)
            if v is UNKNOWN:
                return UNKNOWN
            out.append(v)
    return out


def _eval_call(node: ast.Call, env: dict[str, Any]) -> Any:  # noqa: C901
    if node.keywords:
        # only `encoding=`/`errors=` style keywords on bytes/str are worth handling
        kw = {k.arg: _eval(k.value, env) for k in node.keywords}
        if None in kw or any(v is UNKNOWN or not isinstance(v, str) for v in kw.values()):
            return UNKNOWN
    else:
        kw = {}
    func = node.func

    if isinstance(func, ast.Name):
        name = func.id
        if name in env:  # shadowed builtin
            return UNKNOWN
        if name == "map" and len(node.args) == 2 and isinstance(node.args[0], ast.Name):
            fn = {"chr": chr, "str": str, "ord": ord, "int": int}.get(node.args[0].id)
            items = _iterable(_eval(node.args[1], env))
            if fn is None or items is None or node.args[0].id in env:
                return UNKNOWN
            return [fn(i) for i in items]
        args = _eval_all(node.args, env)
        if args is None:
            return UNKNOWN
        if name == "chr" and len(args) == 1 and isinstance(args[0], int):
            return chr(args[0])
        if name == "ord" and len(args) == 1 and isinstance(args[0], (str, bytes)):
            return ord(args[0])
        if name == "str" and len(args) == 1 and isinstance(args[0], (str, int)):
            return str(args[0])
        if name == "str" and 1 <= len(args) <= 3 and isinstance(args[0], bytes):
            return str(args[0], *[a for a in args[1:] if isinstance(a, str)], **kw)
        if name in {"bytes", "bytearray"}:
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                return bytes(args[0])
            if len(args) >= 1 and isinstance(args[0], str):
                return bytes(args[0], *args[1:], **kw)
            return UNKNOWN
        if name in {"list", "tuple"} and len(args) == 1:
            items = _iterable(args[0])
            if items is None:
                return UNKNOWN
            return items if name == "list" else tuple(items)
        if name == "reversed" and len(args) == 1:
            items = _iterable(args[0])
            return UNKNOWN if items is None else items[::-1]
        if name == "range" and 1 <= len(args) <= 3 and all(isinstance(a, int) for a in args):
            r = range(*args)
            return list(r) if len(r) <= _MAX_ITEMS else UNKNOWN
        if name == "len" and len(args) == 1 and isinstance(args[0], (str, bytes, list, tuple)):
            return len(args[0])
        return UNKNOWN

    if isinstance(func, ast.Attribute):
        method = func.attr
        # bytes.fromhex('...')  /  str.join(sep, it)
        if isinstance(func.value, ast.Name) and func.value.id in {"bytes", "str"} and func.value.id not in env:
            args = _eval_all(node.args, env)
            if args is None:
                return UNKNOWN
            if func.value.id == "bytes" and method == "fromhex" and len(args) == 1 and isinstance(args[0], str):
                return bytes.fromhex(args[0])
            if func.value.id == "str" and method == "join" and len(args) == 2:
                recv = args[0]
                return _join(recv, args[1])
            return UNKNOWN
        recv = _eval(func.value, env)
        if recv is UNKNOWN or not isinstance(recv, (str, bytes)):
            return UNKNOWN
        args = _eval_all(node.args, env)
        if args is None:
            return UNKNOWN
        if method == "join" and len(args) == 1:
            return _join(recv, args[0])
        if method == "decode" and isinstance(recv, bytes):
            return recv.decode(*[a for a in args if isinstance(a, str)], **kw)
        if method == "encode" and isinstance(recv, str):
            return recv.encode(*[a for a in args if isinstance(a, str)], **kw)
        if method == "replace" and len(args) == 2 and all(type(a) is type(recv) for a in args):
            return recv.replace(*args)
        if method == "split" and len(args) <= 1 and (not args or type(args[0]) is type(recv)):
            return recv.split(*args)
        if method in _STR_METHODS_NOARG and not args:
            return getattr(recv, method)()
        if method in {"removeprefix", "removesuffix"} and len(args) == 1 and type(args[0]) is type(recv):
            return getattr(recv, method)(args[0])
    return UNKNOWN


def _join(sep: Any, seq: Any) -> Any:
    items = _iterable(seq)
    if items is None or not isinstance(sep, (str, bytes)):
        return UNKNOWN
    if isinstance(seq, (str, bytes)):  # ''.join('abc') iterates characters
        items = list(seq) if isinstance(seq, str) else [bytes([b]) for b in seq]
    if not all(type(i) is type(sep) for i in items):
        return UNKNOWN
    return sep.join(items)


# --------------------------------------------------------------------------
# Tree rewriting
# --------------------------------------------------------------------------


def _bound_names(node: ast.AST) -> set[str]:
    """Names (re)bound or possibly mutated anywhere inside ``node``."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            out.update((a.asname or a.name.split(".")[0]) for a in n.names)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            out.update(n.names)
        elif isinstance(n, ast.MatchAs) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.MatchStar) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _MUTATORS:
            root = _root_name(n.func.value)
            if root:
                out.add(root)
        elif isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(n.ctx, (ast.Store, ast.Del)):
            root = _root_name(n.value)
            if root:
                out.add(root)
    return out


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _param_names(args: ast.arguments) -> set[str]:
    names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


class _Folder(ast.NodeTransformer):
    def __init__(self) -> None:
        self.env: dict[str, Any] = {}
        self.folded = 0

    # -- expressions -------------------------------------------------------
    def visit(self, node: ast.AST) -> ast.AST:
        if isinstance(node, ast.expr) and not isinstance(node, ast.Constant):
            ctx = getattr(node, "ctx", None)
            if not isinstance(ctx, (ast.Store, ast.Del)):
                val = evaluate(node, self.env)
                if isinstance(val, str):
                    self.folded += 1
                    return ast.copy_location(ast.Constant(value=val), node)
        return super().visit(node)

    def _scoped(self, node: ast.AST, hidden: set[str]) -> ast.AST:
        saved = self.env
        self.env = {k: v for k, v in saved.items() if k not in hidden}
        try:
            return self.generic_visit(node)
        finally:
            self.env = saved

    def visit_Lambda(self, node: ast.Lambda) -> ast.AST:
        return self._scoped(node, _param_names(node.args))

    def _comp(self, node: ast.AST) -> ast.AST:
        hidden = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        return self._scoped(node, hidden)

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _comp

    def visit_Call(self, node: ast.Call) -> ast.AST:
        node = self.generic_visit(node)  # type: ignore[assignment]
        if isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
            root = _root_name(node.func.value)
            if root:
                self.env.pop(root, None)
        return node

    def visit_NamedExpr(self, node: ast.NamedExpr) -> ast.AST:
        node.value = self.visit(node.value)  # type: ignore[assignment]
        val = evaluate(node.value, self.env)
        if val is UNKNOWN:
            self.env.pop(node.target.id, None)
        else:
            self.env[node.target.id] = val
        return node

    # -- statements --------------------------------------------------------
    def _forget(self, names: set[str]) -> None:
        for n in names:
            self.env.pop(n, None)

    def _bind(self, target: ast.AST, value: Any) -> None:
        if isinstance(target, ast.Name):
            if value is UNKNOWN:
                self.env.pop(target.id, None)
            else:
                self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            elts = target.elts
            if (
                isinstance(value, _SEQ)
                and len(value) == len(elts)
                and not any(isinstance(e, ast.Starred) for e in elts)
            ):
                for e, v in zip(elts, value):
                    self._bind(e, v)
            else:
                self._forget(_bound_names(target))
        else:
            self._forget(_bound_names(target))
            root = _root_name(target)
            if root:
                self.env.pop(root, None)

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        node.value = self.visit(node.value)  # type: ignore[assignment]
        val = evaluate(node.value, self.env)
        for t in node.targets:
            self._bind(t, val)
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST:
        if node.value is not None:
            node.value = self.visit(node.value)  # type: ignore[assignment]
            self._bind(node.target, evaluate(node.value, self.env))
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AST:
        node.value = self.visit(node.value)  # type: ignore[assignment]
        if isinstance(node.target, ast.Name):
            synth = ast.BinOp(
                left=ast.Name(id=node.target.id, ctx=ast.Load()), op=node.op, right=node.value
            )
            self._bind(node.target, evaluate(synth, self.env))
        else:
            self._bind(node.target, UNKNOWN)
        return node

    def visit_Delete(self, node: ast.Delete) -> ast.AST:
        self._forget(_bound_names(node))
        return node

    def visit_Import(self, node: ast.Import) -> ast.AST:
        self._forget(_bound_names(node))
        return node

    visit_ImportFrom = visit_Import

    def visit_If(self, node: ast.If) -> ast.AST:
        node.test = self.visit(node.test)  # type: ignore[assignment]
        before = self.env
        self.env = dict(before)
        node.body = [self.visit(s) for s in node.body]  # type: ignore[misc]
        after_body = self.env
        self.env = dict(before)
        node.orelse = [self.visit(s) for s in node.orelse]  # type: ignore[misc]
        after_else = self.env
        self.env = {
            k: v for k, v in after_body.items() if k in after_else and after_else[k] == v and type(after_else[k]) is type(v)
        }
        return node

    def _loopish(self, node: ast.AST) -> ast.AST:
        # Visit header expressions with the pre-loop env, then forget everything the
        # statement can rebind *before* the body so loop-carried values never leak.
        if isinstance(node, (ast.For, ast.AsyncFor)):
            node.iter = self.visit(node.iter)  # type: ignore[assignment]
        elif isinstance(node, ast.While):
            self._forget(_bound_names(node))
            node.test = self.visit(node.test)  # type: ignore[assignment]
        self._forget(_bound_names(node))
        for field in ("body", "handlers", "orelse", "finalbody", "cases"):
            if hasattr(node, field):
                setattr(node, field, [self.visit(s) for s in getattr(node, field)])
        self._forget(_bound_names(node))
        return node

    visit_For = visit_AsyncFor = visit_While = visit_Try = visit_TryStar = visit_Match = _loopish

    def visit_With(self, node: ast.With) -> ast.AST:
        for item in node.items:
            item.context_expr = self.visit(item.context_expr)  # type: ignore[assignment]
            if item.optional_vars is not None:
                self._bind(item.optional_vars, UNKNOWN)
        node.body = [self.visit(s) for s in node.body]  # type: ignore[misc]
        return node

    visit_AsyncWith = visit_With

    def _def(self, node: Any) -> ast.AST:
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        if hasattr(node, "args"):
            node.args.defaults = [self.visit(d) for d in node.args.defaults]
            hidden = _param_names(node.args)
        else:
            hidden = set()
        saved = self.env
        self.env = {k: v for k, v in saved.items() if k not in hidden}
        node.body = [self.visit(s) for s in node.body]
        self.env = saved
        # global/nonlocal rebinding inside the body invalidates outer constants
        for n in ast.walk(node):
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                self._forget(set(n.names))
        self.env.pop(node.name, None)
        return node

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _def


def fold_constants(tree: ast.AST) -> ast.AST:
    """Return a constant-folded *copy* of ``tree`` (the input is not modified)."""
    folder = _Folder()
    folded = folder.visit(copy.deepcopy(tree))
    return ast.fix_missing_locations(folded)
