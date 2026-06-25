from __future__ import annotations

from pathlib import Path

from dnx.output.markdown_report import build_markdown


def write_text_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    path = output_dir / f"{domain}-report.txt"
    # Markdown is readable as plain text and keeps report parity.
    path.write_text(build_markdown(result), encoding="utf-8")
    return path
