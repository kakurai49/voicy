"""Keep Voicy's reviewed public bytes; common Pages core handles packaging."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def prepare(root: Path, stage: Path) -> None:
    """Validate the entire repository boundary and copy only public files."""
    root, stage = Path(root), Path(stage)
    if not stage.is_dir() or stage.is_symlink() or any(stage.iterdir()):
        raise ValueError("EMPTY_STAGE_REQUIRED")
    if root.resolve() == stage.resolve() or root.resolve() in stage.resolve().parents:
        raise ValueError("SOURCE_STAGE_OVERLAP")
    spec = importlib.util.spec_from_file_location("voicy_site_validator", root / ".github/pages/build_site.py")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    files = validator.collect_files(root)
    validator.validate_site(files)
    for relative, raw in sorted(files.items()):
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
