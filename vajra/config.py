"""
Central path/config resolution so VajraLink runs the same on macOS, Linux and Windows.

The original handover assumed ``vajra-link/`` and ``targets/`` were siblings (``../targets/VulnerableApp``).
In this checkout the project root *is* the vajra-link folder and the target lives in ``./targets``.
``resolve_source_path`` accepts either layout (or an explicit ``VAJRA_TARGET_DIR`` override).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Bundled demo default only (SasanLabs/VulnerableApp shipped for quick-start). Any scan of another project passes its own path.
DEFAULT_TARGET_REL = "targets/VulnerableApp"
DEFAULT_TARGET_URL = os.getenv("VAJRA_TARGET_URL", "http://127.0.0.1:9090")


def _candidates(requested: Optional[str]) -> list[Path]:
    env_override = os.getenv("VAJRA_TARGET_DIR")
    out: list[Path] = []
    if env_override:
        out.append(Path(env_override))
    if requested:
        req = Path(requested)
        out.append(req if req.is_absolute() else Path.cwd() / req)
        out.append(PROJECT_ROOT / requested)
        # Tolerate the legacy "../targets/X" spelling: also try "<root>/targets/X"
        norm = requested.replace("\\", "/")
        if norm.startswith("../"):
            out.append(PROJECT_ROOT / norm[3:])
    out.append(PROJECT_ROOT / DEFAULT_TARGET_REL)
    out.append(PROJECT_ROOT.parent / DEFAULT_TARGET_REL)
    return out


def resolve_source_path(requested: Optional[str] = None) -> str:
    """Return an absolute path to the requested source directory.

    If the requested folder exists (in any accepted spelling) that is returned. If it does NOT exist, the
    requested location itself is returned (not silently swapped for the default VulnerableApp folder), so
    callers can clone into it or reject it. Only when no folder was requested does it fall back to the default.
    """
    if requested:
        req = Path(requested)
        spellings = [req if req.is_absolute() else Path.cwd() / req, PROJECT_ROOT / requested]
        norm = requested.replace("\\", "/")
        if norm.startswith("../"):
            spellings.append(PROJECT_ROOT / norm[3:])
        for c in spellings:
            if c.is_dir():
                return str(c.resolve())
        # Not on disk yet: return the requested location itself (never the default folder).
        return str(spellings[1].resolve())
    cands = _candidates(None)
    for c in cands:
        if c.is_dir():
            return str(c.resolve())
    return str(cands[0].resolve())
