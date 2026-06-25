from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable


def _dedup(values: Iterable[str]) -> list[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})


def _write_lines(path: Path, values: Iterable[str]) -> Path:
    data = _dedup(values)
    path.write_text("\n".join(data) + ("\n" if data else ""), encoding="utf-8")
    return path


def write_asset_exports(result: dict, output_dir: Path) -> list[Path]:
    """Write pipeline-friendly asset lists beside the main reports.

    These files make dnsRecon easy to chain into tools such as httpx, nuclei,
    ffuf, naabu, or a manual review workflow without parsing the full JSON.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    paths: list[Path] = []

    subdomains = result.get("subdomains", {})
    all_subdomains = subdomains.get("unique_subdomains", []) or []
    verified = [item.get("name") for item in subdomains.get("verified_subdomains", []) or []]
    active = [item.get("name") for item in subdomains.get("active", []) or [] if item.get("resolved") and not item.get("wildcard_match")]

    ips: list[str] = []
    ips.extend(result.get("records", {}).get("A", {}).get("values", []) or [])
    ips.extend(result.get("records", {}).get("AAAA", {}).get("values", []) or [])
    for item in subdomains.get("verified_subdomains", []) or []:
        ips.extend(item.get("addresses", []) or [])
    for item in result.get("nameservers", {}).get("servers", []) or []:
        ips.extend(item.get("ipv4", []) or [])
        ips.extend(item.get("ipv6", []) or [])

    urls: list[str] = []
    for host in result.get("http", []) or []:
        for url in host.get("urls", []) or []:
            if url.get("alive") or url.get("status_code"):
                urls.append(url.get("url", ""))

    nuclei_targets = urls or [f"https://{host}" for host in _dedup([domain, *verified, *active])]

    paths.append(_write_lines(output_dir / f"{domain}-subdomains.txt", all_subdomains))
    paths.append(_write_lines(output_dir / f"{domain}-verified-subdomains.txt", verified))
    paths.append(_write_lines(output_dir / f"{domain}-active-subdomains.txt", active))
    paths.append(_write_lines(output_dir / f"{domain}-ips.txt", ips))
    paths.append(_write_lines(output_dir / f"{domain}-live-urls.txt", urls))
    paths.append(_write_lines(output_dir / f"{domain}-nuclei-targets.txt", nuclei_targets))

    takeover_path = output_dir / f"{domain}-takeover-candidates.csv"
    with takeover_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["asset", "cname", "provider", "confidence", "source", "note"])
        for item in result.get("takeover", {}).get("candidates", []) or []:
            writer.writerow([
                item.get("asset", ""),
                item.get("cname", ""),
                item.get("provider", ""),
                item.get("confidence", ""),
                item.get("source", ""),
                "Provider fingerprint only; manually verify before reporting exploitable takeover.",
            ])
    paths.append(takeover_path)

    return paths
