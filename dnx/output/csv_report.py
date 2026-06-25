from __future__ import annotations

import csv
from pathlib import Path


def write_csv_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    path = output_dir / f"{domain}-report.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["category", "name", "value", "status", "source", "severity", "recommendation"])
        for rtype, item in result.get("records", {}).items():
            values = item.get("values", []) or [""]
            for value in values:
                writer.writerow(["dns_record", rtype, value, item.get("error") or "ok", item.get("resolver") or item.get("nameserver") or "", "", ""])
        for ns in result.get("nameservers", {}).get("servers", []):
            writer.writerow(["nameserver", ns.get("host"), ", ".join(ns.get("ipv4", []) + ns.get("ipv6", [])), ns.get("status"), ns.get("provider_hint") or "DNS NS", "", ""])
        for issue in result.get("dns_health", {}).get("issues", []):
            writer.writerow(["dns_health", issue.get("title"), issue.get("evidence"), "open", "dnsRecon health", issue.get("severity"), "Review DNS health issue"])
        for name in result.get("subdomains", {}).get("unique_subdomains", []):
            sources = ", ".join(result.get("subdomains", {}).get("source_map", {}).get(name, []))
            writer.writerow(["subdomain", name, "", "discovered", sources, "", ""])
        for item in result.get("subdomains", {}).get("verified_subdomains", []):
            values = ", ".join(item.get("addresses", []) + item.get("cname", []))
            writer.writerow(["verified_subdomain", item.get("name"), values, "resolved", ", ".join(item.get("sources", [])), "", ""])
        for item in result.get("takeover", {}).get("candidates", []):
            writer.writerow(["takeover_candidate", item.get("asset"), item.get("cname"), item.get("confidence"), item.get("provider"), "MEDIUM", "Manually verify provider resource ownership"])
        for host in result.get("http", []):
            for url in host.get("urls", []):
                writer.writerow(["http_probe", host.get("host"), url.get("url"), url.get("status_code") or url.get("error"), url.get("server") or "HTTP", "", url.get("title") or ""])
        for item in result.get("tls", []):
            writer.writerow(["tls_probe", item.get("host"), item.get("not_after"), "ok" if item.get("ok") else item.get("error"), "TLS", "", f"expires_in_days={item.get('expires_in_days')}"])
        for finding in result.get("findings", []):
            writer.writerow(["finding", finding.get("title"), finding.get("evidence"), "open", finding.get("id") or "dnsRecon findings engine", finding.get("severity"), finding.get("recommendation")])
    return path
