"""Host availability of external binaries backing registered tools.

The registry and ``tools_manifest.json`` stay complete on every host; this
module answers the narrower question "can this tool actually run here?" so the
planner is not offered tools whose binary is missing (which otherwise shows up
only as an exit=127 after the task was already scheduled).

Requirements are derived from the tool's own contract — an explicit
``ToolSpec.dependencies`` entry wins, otherwise the leading token of the
command template / argv template is used.
"""

from __future__ import annotations

import shlex
import shutil
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

# Wrappers that may precede the real binary in a template.
_WRAPPER_TOKENS = {"timeout", "nice", "env", "sudo", "time", "stdbuf", "command"}
# Interpreters: their presence never gates a tool by itself.
_INTERPRETERS = {"sh", "bash", "dash", "python", "python3", "perl", "ruby"}


@lru_cache(maxsize=256)
def _binary_exists(binary: str) -> bool:
    if not binary:
        return False
    if "/" in binary:
        return Path(binary).exists()
    if shutil.which(binary) is not None:
        return True
    # Console scripts installed into the running virtualenv are not
    # necessarily on PATH; the shell executor prepends that directory too.
    return (Path(sys.executable).resolve().parent / binary).exists()


def clear_cache() -> None:
    """Drop the cached PATH lookups (used by tests and after env changes)."""
    _binary_exists.cache_clear()


def _leading_binary(command: str) -> str:
    """Extract the first real executable token from a shell command template."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    idx = 0
    while idx < len(tokens):
        token = tokens[idx].strip("'\"")
        if not token:
            idx += 1
            continue
        if "=" in token and not token.startswith("/"):
            idx += 1  # VAR=value prefix
            continue
        if token in _WRAPPER_TOKENS:
            idx += 1
            if idx < len(tokens) and tokens[idx].lstrip("-").isdigit():
                idx += 1
            continue
        return Path(token).name
    return ""


def required_binaries(spec: Any) -> list[str]:
    """Binaries a tool needs on PATH, derived from its declared contract."""
    declared = [
        str(d).strip() for d in (getattr(spec, "dependencies", None) or [])
    ]
    # Legacy/naive derivations sometimes recorded an env assignment or an
    # unresolved placeholder instead of a binary — ignore those and fall
    # back to parsing the command template.
    declared = [
        d for d in declared
        if d and "=" not in d and not d.startswith("{") and " " not in d
    ]
    if declared:
        return declared
    template = str(getattr(spec, "command_template", "") or "")
    if not template:
        shell_args = getattr(spec, "shell_args", None) or []
        template = " ".join(str(a) for a in shell_args)
    if not template:
        return []
    binary = _leading_binary(template)
    if not binary or binary in _INTERPRETERS or binary.startswith("{"):
        return []
    return [binary]


def missing_binaries(spec: Any) -> list[str]:
    return [b for b in required_binaries(spec) if not _binary_exists(b)]


def is_available(spec: Any) -> bool:
    """True when every binary the tool needs is present on this host."""
    return not missing_binaries(spec)


def filter_available(
    specs: Iterable[Any], unavailable: Iterable[str] = ()
) -> list[Any]:
    """Keep specs that are runnable here; ``unavailable`` forces exclusion."""
    blocked = {str(name) for name in unavailable}
    return [
        spec for spec in specs
        if getattr(spec, "name", "") not in blocked and is_available(spec)
    ]
