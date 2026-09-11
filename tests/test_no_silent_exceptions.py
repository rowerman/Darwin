"""Static guards against silently swallowed exceptions and undefined names.

Two defects in this class went unnoticed for weeks: an undefined ``_re`` alias
in ``orchestration/planning.py`` (which silently disabled RAG knowledge in
every generated plan) and two impacket tools referencing an undefined
``stdout``.  Both were hidden by ``except Exception: pass``.

Policy enforced here (``darwin/`` is the production package):

1. ``except ...: pass`` is allowed only when the handler line carries an
   explicit ``# silent-ok: <reason>`` marker; anything else must log.
2. No module may reference a name that is neither bound in scope nor a builtin
   (the ``_re`` / ``stdout`` class of bug).
"""

from __future__ import annotations

import ast
import builtins
import pathlib
import symtable

import pytest

DARWIN_ROOT = pathlib.Path(__file__).resolve().parents[1] / "darwin"
_BUILTINS = set(dir(builtins))


def _python_files() -> list[pathlib.Path]:
    return sorted(DARWIN_ROOT.rglob("*.py"))


def _source(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _relative(path: pathlib.Path) -> str:
    return str(path.relative_to(DARWIN_ROOT.parent))


def test_no_unmarked_silent_exception_handlers():
    offenders: list[str] = []
    for path in _python_files():
        source = _source(path)
        lines = source.split("\n")
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover - syntax errors fail elsewhere
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if len(node.body) != 1 or not isinstance(node.body[0], ast.Pass):
                continue
            if "# silent-ok" in lines[node.lineno - 1]:
                continue
            offenders.append(f"{_relative(path)}:{node.lineno}")
    assert not offenders, (
        "Silent exception handlers must log or carry '# silent-ok: <reason>':\n  "
        + "\n  ".join(offenders)
    )


def _module_level_bindings(table: symtable.SymbolTable) -> set[str]:
    return {
        symbol.get_name()
        for symbol in table.get_symbols()
        if symbol.is_assigned() or symbol.is_imported()
        or symbol.is_namespace() or symbol.is_parameter()
    }


def _walk_scopes(table: symtable.SymbolTable):
    yield table
    for child in table.get_children():
        yield from _walk_scopes(child)


def _undefined_names(path: pathlib.Path) -> list[str]:
    try:
        table = symtable.symtable(_source(path), str(path), "exec")
    except SyntaxError:  # pragma: no cover
        return []
    module_bindings = _module_level_bindings(table)
    found: list[str] = []
    for scope in _walk_scopes(table):
        for symbol in scope.get_symbols():
            name = symbol.get_name()
            if not symbol.is_referenced():
                continue
            if (symbol.is_assigned() or symbol.is_imported()
                    or symbol.is_parameter() or symbol.is_free()
                    or symbol.is_namespace()):
                continue
            if name in module_bindings or name in _BUILTINS or name == "__file__":
                continue
            found.append(f"{_relative(path)}:{scope.get_lineno()}: {name}")
    return found


def test_no_undefined_module_names():
    offenders: list[str] = []
    for path in _python_files():
        offenders.extend(_undefined_names(path))
    assert not offenders, (
        "Undefined names referenced in darwin/ (silent NameError risk):\n  "
        + "\n  ".join(sorted(offenders))
    )


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_darwin_modules_compile(path: pathlib.Path):
    """Cheap compile guard so a broken module fails fast."""
    compile(_source(path), str(path), "exec")
