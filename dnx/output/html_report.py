from __future__ import annotations

import html
from pathlib import Path


def _rows(items: list[tuple[str, str]]) -> str:
    return "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in items)


def _list(values: list[str]) -> str:
    if not values:
        return "<em>Not found</em>"
    return "<ul>" + "".join(f"<li><code>{html.escape(str(v))}</code></li>" for v in values[:500]) + "</ul>"


def write_html_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    risk = result.get("risk", {})
    findings = result.get("findings", [])

    records_html = "".join(
        f"<h3>{html.escape(rtype)}</h3>{_list(item.get('values', []))}<p class='muted'>TTL: {html.escape(str(item.get('ttl') or '-'))} | Status: {html.escape(item.get('error') or 'ok')}</p>"
        for rtype, item in result.get("records", {}).items()
    )
    findings_html = "".join(
        f"<article class='finding {html.escape(str(f.get('severity', '')).lower())}'><h3>[{html.escape(str(f.get('severity')))}] {html.escape(str(f.get('title')))}</h3><p><b>Confidence:</b> {html.escape(str(f.get('confidence', 'medium')))}</p><p><b>Evidence:</b> {html.escape(str(f.get('evidence')))}</p><p><b>Recommendation:</b> {html.escape(str(f.get('recommendation')))}</p></article>"
        for f in findings
    ) or "<p>No findings.</p>"
    subdomains = result.get("subdomains", {})
    sub_html = _list(subdomains.get("unique_subdomains", [])[:500])

    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>dnsRecon Report - {html.escape(domain)}</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Arial, sans-serif; background:#08111f; color:#e7edf7; margin:0; }}
    main {{ max-width:1180px; margin:auto; padding:32px; }}
    header {{ background:linear-gradient(135deg,#0e7490,#1e3a8a); padding:28px; border-radius:18px; box-shadow:0 20px 60px rgba(0,0,0,.25); }}
    h1 {{ margin:0 0 8px; }} h2 {{ margin-top:34px; border-bottom:1px solid #263954; padding-bottom:8px; }}
    code {{ background:#101b2e; padding:2px 6px; border-radius:6px; }}
    table {{ width:100%; border-collapse:collapse; background:#0c1728; border-radius:12px; overflow:hidden; }}
    th,td {{ border-bottom:1px solid #1f2f47; padding:10px 12px; text-align:left; vertical-align:top; }}
    th {{ width:220px; color:#93c5fd; }} .muted {{ color:#9ca3af; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-top:18px; }}
    .card {{ background:#0c1728; border:1px solid #1f2f47; border-radius:14px; padding:16px; }}
    .big {{ font-size:30px; font-weight:800; }}
    .finding {{ background:#0c1728; border-left:5px solid #64748b; padding:14px 18px; margin:12px 0; border-radius:10px; }}
    .finding.high,.finding.critical {{ border-color:#ef4444; }} .finding.medium {{ border-color:#f59e0b; }} .finding.low {{ border-color:#3b82f6; }}
    ul {{ line-height:1.7; }}
  </style>
</head>
<body><main>
<header>
  <h1>dnsRecon Report</h1>
  <p>{html.escape(domain)} · generated {html.escape(str(result.get('generated_at')))} · v{html.escape(str(result.get('version')))}</p>
  <div class="cards"><div class="card"><div class="muted">Risk Score</div><div class="big">{html.escape(str(risk.get('score', 'n/a')))} / 100</div><div>{html.escape(str(risk.get('level', 'n/a')))}</div></div><div class="card"><div class="muted">Subdomains</div><div class="big">{html.escape(str(subdomains.get('count', 0)))}</div><div>{html.escape(str(subdomains.get('verified_count', 0)))} verified</div></div><div class="card"><div class="muted">Findings</div><div class="big">{len(findings)}</div><div>open items</div></div></div>
</header>
<h2>Scan Profile</h2><table>{_rows([(k, str(v)) for k,v in result.get('scan_profile', {}).items()])}</table>
<h2>DNS Records</h2>{records_html}
<h2>Subdomains</h2>{sub_html}
<h2>Findings</h2>{findings_html}
</main></body></html>
"""
    path = output_dir / f"{domain}-report.html"
    path.write_text(doc, encoding="utf-8")
    return path
