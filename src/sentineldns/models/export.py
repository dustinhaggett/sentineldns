from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib


def export_joblib(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)


def export_metadata(path: Path, metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"exported_at": datetime.now(timezone.utc).isoformat(), **metadata}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
