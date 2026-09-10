"""Runtime resolution of external resources (wordlists, venv binaries).

Tool registrations must stay machine independent: the ToolSpec ``default``
values that end up in ``tools_manifest.json`` are logical names, and the
concrete filesystem locations are resolved here at call time.  This keeps the
committed manifest identical on every host while still finding the bundled
wordlists and the project virtualenv.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Searched in order; the first existing file wins.
_WORDLIST_ROOTS: tuple[Path, ...] = (
    _PROJECT_ROOT / "wordlists",
    Path("/usr/share/dirb/wordlists"),
    Path("/usr/share/seclists/Discovery/Web-Content"),
    Path("/usr/share/wordlists"),
)


def project_root() -> Path:
    return _PROJECT_ROOT


def venv_bin_dir() -> Path:
    """Directory holding the running interpreter's console scripts."""
    return Path(sys.executable).resolve().parent


def venv_bin(name: str) -> str:
    """Resolve a console script from the running interpreter's bin directory.

    Falls back to whatever is on PATH, then to the bare name so callers can
    surface a normal "not found" error instead of a hardcoded stale path.
    """
    candidate = venv_bin_dir() / name
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    return found or name


def tool_path_env(base_env: dict | None = None) -> dict:
    """Environment for tool subprocesses with the venv bin dir on PATH.

    Keeps command templates machine independent (bare binary names such as
    ``netexec``) while still finding console scripts installed into the
    project virtualenv rather than the system PATH.
    """
    env = dict(base_env if base_env is not None else os.environ)
    bin_dir = str(venv_bin_dir())
    current = env.get("PATH", "")
    if bin_dir not in current.split(os.pathsep):
        env["PATH"] = f"{bin_dir}{os.pathsep}{current}" if current else bin_dir
    return env


def resolve_wordlist(name: str) -> str:
    """Resolve a wordlist by logical name or absolute path.

    Returns an empty string when nothing matches so callers can report a
    clear error instead of running a brute-forcer against a missing file.
    """
    if not name:
        return ""
    candidate = Path(name)
    if candidate.is_absolute():
        return str(candidate) if candidate.exists() else ""
    for root in _WORDLIST_ROOTS:
        resolved = root / name
        if resolved.exists():
            return str(resolved)
    return ""


def default_wordlist() -> str:
    """Preferred directory-brute-force wordlist, or "" when unavailable."""
    # Prefer a bounded general list: the bundled raft-* lists have 60k+
    # entries, which does not fit a single reconnaissance allocation against
    # a dev server.  The larger lists stay selectable via the tool parameter.
    for name in ("common.txt", "raft-large-directories.txt"):
        resolved = resolve_wordlist(name)
        if resolved:
            return resolved
    return ""
