from __future__ import annotations

import json
from pathlib import Path


def write_json_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    path = output_dir / f"{domain}-report.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return path
