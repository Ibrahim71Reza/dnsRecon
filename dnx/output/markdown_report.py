from __future__ import annotations

from pathlib import Path


def _list(values: list[str]) -> str:
    if not values:
        return "- Not found\n"
    return "".join(f"- `{v}`\n" for v in values)


def _kv(data: dict) -> str:
    if not data:
        return "- N/A\n"
    return "".join(f"- **{k}:** `{v}`\n" for k, v in data.items())


def build_markdown(result: dict) -> str:
    domain = result["target"]["domain"]
    risk = result.get("risk", {})
    profile = result.get("scan_profile", {})
    lines = [
        f"# dnsRecon Report: `{domain}`",
        "",
        "## Executive Summary",
        "",
        f"dnsRecon assessed DNS, mail-security, PKI, subdomain-discovery, resolver-consistency, and optional host-probing evidence for `{domain}`.",
        "",
        f"- **Tool version:** `{result.get('version')}`",
        f"- **Mode:** `{result.get('mode')}`",
        f"- **Profile:** `{profile.get('profile')}`",
        f"- **Generated:** `{result.get('generated_at')}`",
        f"- **Duration:** `{result.get('duration_seconds')}s`",
        f"- **Risk score:** `{risk.get('score', 'n/a')}/100` (`{risk.get('level', 'n/a')}`)",
        f"- **Finding counts:** `{risk.get('counts', {})}`",
        f"- **Resolver:** `{profile.get('resolver') or ', '.join(profile.get('effective_resolvers', [])) or 'system default'}`",
        f"- **Active checks:** `{profile.get('active_checks')}`",
        f"- **Passive checks:** `{profile.get('passive_checks')}`",
        f"- **Subdomain verification:** `{profile.get('verify_subdomains')}`",
        f"- **HTTP probing:** `{profile.get('http_probe')}`",
        f"- **TLS probing:** `{profile.get('tls_probe')}`",
        "",
        "## Scan Profile",
        "",
        _kv(profile),
        "",
        "## DNS Records",
        "",
    ]
    for rtype, item in result.get("records", {}).items():
        lines.append(f"### {rtype}")
        lines.append("")
        lines.append(_list(item.get("values", [])))
        lines.append(f"- TTL: `{item.get('ttl') or '-'}`")
        lines.append(f"- Resolver: `{item.get('resolver') or item.get('nameserver') or '-'}`")
        lines.append(f"- Error type: `{item.get('error_type') or '-'}`")
        if item.get("error"):
            lines.append(f"> Status: {item['error']}\n")

    lines.extend(["", "## Nameservers", ""])
    for ns in result.get("nameservers", {}).get("servers", []):
        lines.append(f"- **{ns.get('host')}** — IPv4: `{', '.join(ns.get('ipv4', [])) or '-'}` IPv6: `{', '.join(ns.get('ipv6', [])) or '-'}` Status: `{ns.get('status')}` Provider: `{ns.get('provider_hint') or '-'}`")

    health = result.get("dns_health", {})
    lines.extend(["", "## DNS Health", ""])
    if not health.get("issues"):
        lines.append("- No DNS health issues detected by dnsRecon.")
    for issue in health.get("issues", []):
        lines.append(f"- **[{issue.get('severity')}] {issue.get('title')}** — {issue.get('evidence')}")

    mail = result.get("mail_security", {})
    lines.extend(["", "## Mail Security", ""])
    lines.append("### MX\n" + _list(mail.get("mx", [])))
    lines.append(f"- Providers: `{', '.join(mail.get('mx_providers', [])) or '-'}`")
    lines.append("### SPF\n" + _list(mail.get("spf", {}).get("records", [])))
    lines.append(f"- Includes: `{', '.join(mail.get('spf', {}).get('includes', [])) or '-'}`")
    lines.append(f"- DNS lookup estimate: `{mail.get('spf', {}).get('dns_lookup_estimate', 0)}`")
    if mail.get("spf", {}).get("issues"):
        lines.append("- Issues: `" + "; ".join(mail.get("spf", {}).get("issues", [])) + "`")
    lines.append("### DMARC\n" + _list(mail.get("dmarc", {}).get("records", [])))
    lines.append(f"- Policy: `{mail.get('dmarc', {}).get('policy') or '-'}`")
    lines.append(f"- Subdomain policy: `{mail.get('dmarc', {}).get('subdomain_policy') or '-'}`")
    lines.append(f"- RUA: `{mail.get('dmarc', {}).get('rua') or '-'}`")
    dkim_found = [f"{d['selector']}: {', '.join(d['records'])}" for d in mail.get("dkim", {}).get("found", [])]
    lines.append("### DKIM common selectors\n" + _list(dkim_found))
    lines.append("### MTA-STS\n" + _list(mail.get("mta_sts", {}).get("records", [])))
    lines.append("### TLS-RPT\n" + _list(mail.get("tls_rpt", {}).get("records", [])))
    lines.append("### BIMI\n" + _list(mail.get("bimi", {}).get("records", [])))

    lines.extend(["", "## DNSSEC", ""])
    dnssec = result.get("dnssec", {})
    lines.append(f"- Appears enabled: `{dnssec.get('appears_enabled')}`")
    lines.append(f"- State: `{dnssec.get('state')}`")
    lines.append("- DS records:")
    lines.append(_list(dnssec.get("ds_records", [])))
    if dnssec.get("algorithms"):
        lines.append("- Algorithms:")
        for algo in dnssec.get("algorithms", []):
            lines.append(f"  - `{algo.get('algorithm')}` {algo.get('name')} weak=`{algo.get('weak')}`")

    lines.extend(["", "## CAA", ""])
    lines.append(_list(result.get("caa", {}).get("records", [])))

    lines.extend(["", "## Reverse DNS", ""])
    for ptr in result.get("reverse_dns", []):
        lines.append(f"- `{ptr.get('ip')}` -> {', '.join(ptr.get('ptr', [])) or 'No PTR'}")

    lines.extend(["", "## Zone Transfer", ""])
    zt = result.get("zone_transfer", [])
    if not zt:
        lines.append("- Not run or no nameservers available.")
    for item in zt:
        status = "VULNERABLE" if item.get("vulnerable") else "not allowed"
        lines.append(f"- `{item.get('nameserver')}` / `{item.get('ip')}`: **{status}** — {item.get('error') or 'AXFR returned data'}")

    sub = result.get("subdomains", {})
    lines.extend(["", "## Subdomains", ""])
    lines.append(f"- Total unique: **{sub.get('count', 0)}**")
    lines.append(f"- Verified live: **{sub.get('verified_count', 0)}**")
    lines.append(f"- Estimated DNS queries used: **{sub.get('dns_queries_estimated', 0)} / {sub.get('dns_queries_budget', 0)}**")
    passive = sub.get("passive", {})
    if passive.get("sources"):
        lines.append("\n### Passive source counts")
        for src in passive.get("sources", []):
            lines.append(f"- `{src.get('source')}`: `{len(src.get('subdomains', []))}` ({src.get('error') or 'ok'})")
    lines.append("\n### Unique names")
    for name in sub.get("unique_subdomains", [])[:250]:
        srcs = ", ".join(sub.get("source_map", {}).get(name, [])) or "unknown"
        lines.append(f"- `{name}` — {srcs}")
    if sub.get("count", 0) > 250:
        lines.append(f"- ... {sub.get('count', 0) - 250} more in JSON report")

    if sub.get("verified_subdomains"):
        lines.append("\n### Verified live subdomains")
        for item in sub.get("verified_subdomains", [])[:250]:
            values = ", ".join(item.get("addresses", []) + item.get("cname", [])) or "resolved"
            lines.append(f"- `{item.get('name')}` -> `{values}`")

    takeover = result.get("takeover", {})
    lines.extend(["", "## Takeover Candidates", ""])
    if not takeover.get("candidates"):
        lines.append("- No provider-fingerprint takeover candidates detected.")
    else:
        lines.append(f"- Count: `{takeover.get('count')}`")
        lines.append(f"- Note: {takeover.get('note')}")
        for item in takeover.get("candidates", [])[:100]:
            lines.append(f"- `{item.get('asset')}` -> `{item.get('cname')}` provider=`{item.get('provider')}` confidence=`{item.get('confidence')}`")

    if result.get("http"):
        lines.extend(["", "## HTTP Probe", ""])
        for host in result.get("http", [])[:250]:
            alive = host.get("alive")
            lines.append(f"### `{host.get('host')}` alive=`{alive}`")
            for url in host.get("urls", []):
                lines.append(f"- `{url.get('url')}` -> `{url.get('status_code') or '-'}` title=`{url.get('title') or '-'}` server=`{url.get('server') or '-'}` error=`{url.get('error') or '-'}`")

    if result.get("tls"):
        lines.extend(["", "## TLS Inspection", ""])
        for item in result.get("tls", [])[:250]:
            lines.append(f"- `{item.get('host')}` ok=`{item.get('ok')}` expires_in_days=`{item.get('expires_in_days')}` SANs=`{len(item.get('san_domains', []))}` error=`{item.get('error') or '-'}`")

    comparison = result.get("resolver_comparison", {})
    lines.extend(["", "## Resolver Comparison", ""])
    if not comparison.get("enabled"):
        lines.append("- Not enabled.")
    else:
        lines.append(f"- Resolvers: `{', '.join(comparison.get('resolvers', []))}`")
        lines.append(f"- Difference count: `{comparison.get('difference_count')}`")
        for diff in comparison.get("differences", []):
            lines.append(f"### {diff.get('record_type')}")
            for variant in diff.get("variants", []):
                lines.append(f"- `{', '.join(variant.get('resolvers', []))}` -> `{', '.join(variant.get('values', [])) or '-'}` error_type=`{variant.get('error_type')}`")

    lines.extend(["", "## Findings", ""])
    if not result.get("findings"):
        lines.append("- No findings.")
    for item in result.get("findings", []):
        lines.append(f"### [{item.get('severity')}] {item.get('title')}")
        lines.append(f"- **ID:** `{item.get('id')}`")
        lines.append(f"- **Category:** {item.get('category', 'General')}")
        lines.append(f"- **Confidence:** {item.get('confidence', 'medium')}")
        lines.append(f"- **Evidence:** {item.get('evidence')}")
        lines.append(f"- **Recommendation:** {item.get('recommendation')}")
        lines.append("")

    whois = result.get("whois", {})
    lines.extend(["", "## WHOIS/RDAP Summary", ""])
    if whois.get("error"):
        lines.append(f"- Error: `{whois['error']}`")
    else:
        lines.append(f"- Source: `{whois.get('source')}`")
        lines.append(f"- WHOIS server: `{whois.get('server', '-')}`")
        summary = whois.get("summary", {})
        for key, values in summary.items():
            lines.append(f"- **{key}:** {values}")

    return "\n".join(lines).strip() + "\n"


def write_markdown_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = result["target"]["domain"]
    path = output_dir / f"{domain}-report.md"
    path.write_text(build_markdown(result), encoding="utf-8")
    return path
