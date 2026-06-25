from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def print_banner() -> None:
    banner = Text("dnsRecon", style="bold cyan")
    subtitle = Text("Terminal-first DNS intelligence for authorized users", style="dim")
    console.print(Panel.fit(f"{banner}\n{subtitle}", border_style="cyan"))


def _csv(values: list | tuple | set, fallback: str = "-") -> str:
    vals = [str(v) for v in values if str(v)] if values else []
    return "\n".join(vals) if vals else fallback


def _single(value, fallback: str = "-") -> str:
    return str(value) if value not in (None, "", []) else fallback


def _section(title: str) -> None:
    console.print(f"\n[bold cyan]{title}[/bold cyan]")




def _limit_items(items, result: dict):
    limit = int(result.get("scan_profile", {}).get("terminal_limit", 1000) or 0)
    if limit <= 0:
        return list(items), 0
    data = list(items)
    hidden = max(0, len(data) - limit)
    return data[:limit], hidden


def _executive_view(result: dict) -> None:
    _section("Executive Intelligence")
    risk = result.get("risk", {})
    sub = result.get("subdomains", {})
    dns_health = result.get("dns_health", {})
    mail = result.get("mail_security", {})
    dnssec = result.get("dnssec", {})
    caa = result.get("caa", {})
    external = result.get("external_tools", {})
    table = Table(show_lines=True)
    table.add_column("Area", style="bold")
    table.add_column("Signal")
    table.add_column("Operator meaning")
    table.add_row("Risk", f"{risk.get('score', 'n/a')}/100 · {risk.get('level', 'n/a')}", f"{sum(risk.get('counts', {}).values()) if isinstance(risk.get('counts'), dict) else 0} findings weighted by severity/confidence")
    table.add_row("DNS health", f"{dns_health.get('issue_count', 0)} issues", "Delegation, SOA/NS, TTL, CNAME conflict and TXT bloat checks")
    spf_sig = mail.get('spf', {}).get('status', mail.get('spf', {}).get('found'))
    dmarc_sig = mail.get('dmarc', {}).get('status', mail.get('dmarc', {}).get('found'))
    table.add_row("Mail posture", f"SPF={spf_sig} DMARC={dmarc_sig}", "Email authentication and transport-security signals")
    table.add_row("PKI/DNSSEC", f"CAA={caa.get('found')} DNSSEC={dnssec.get('state', '-')}", "Certificate issuance control and chain-of-trust hints")
    table.add_row("Subdomains", f"{sub.get('count', 0)} unique · {sub.get('verified_count', 0)} verified", "Native passive/active plus optional OSS-normalized sources")
    available = sum(1 for t in external.get('tools', []) if t.get('available'))
    requested = len(external.get('tools', []) or [])
    table.add_row("OSS adapters", f"{available}/{requested} available" if external.get('enabled') else "disabled", "Installed tools are used as evidence amplifiers, not hard dependencies")
    console.print(table)


def _maybe_hidden(hidden: int, label: str) -> None:
    if hidden > 0:
        console.print(f"[dim]... {hidden} more {label} hidden by --terminal-limit. Use --terminal-limit 0 to print everything.[/dim]")

def print_terminal_report(result: dict) -> None:
    """Render the canonical scan object directly in the terminal.

    Reports are optional in v1; this terminal view is the default source of truth
    for an operator running dnsRecon interactively.
    """
    target = result.get("target", {})
    risk = result.get("risk", {})
    profile = result.get("scan_profile", {})
    sub = result.get("subdomains", {})
    findings = result.get("findings", [])

    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {target.get('domain')}\n"
            f"[bold]Mode/Profile:[/bold] {result.get('mode')} / {profile.get('profile')}\n"
            f"[bold]Risk:[/bold] {risk.get('score', 'n/a')}/100 ({risk.get('level', 'n/a')})\n"
            f"[bold]Subdomains:[/bold] {sub.get('count', 0)} total · {sub.get('verified_count', 0)} verified\n"
            f"[bold]Findings:[/bold] {len(findings)} · [bold]Duration:[/bold] {result.get('duration_seconds')}s",
            title="dnsRecon Result",
            border_style="green" if (risk.get("score") or 0) >= 70 else "yellow",
        )
    )

    _executive_view(result)
    _module_timings(result.get("module_timings", {}))
    _reliability(result.get("reliability", {}))
    _scan_profile(profile)
    _records(result.get("records", {}))
    _nameservers(result.get("nameservers", {}))
    _dns_health(result.get("dns_health", {}))
    _mail_security(result.get("mail_security", {}))
    _dnssec(result.get("dnssec", {}))
    _caa(result.get("caa", {}))
    _service_records(result.get("service_records", {}))
    _reverse_dns(result.get("reverse_dns", []))
    _wildcard(result.get("wildcard", {}))
    _zone_transfer(result.get("zone_transfer", []))
    _subdomains(sub)
    _external_tools(result.get("external_tools", {}))
    _takeover(result.get("takeover", {}))
    _http(result.get("http", []))
    _tls(result.get("tls", []))
    _resolver_comparison(result.get("resolver_comparison", {}))
    _whois(result.get("whois", {}))
    _findings(findings)
    _next_steps(result)


def _module_timings(timings: dict) -> None:
    if not timings:
        return
    _section("Module Timing")
    table = Table(show_lines=False)
    table.add_column("Module", style="bold")
    table.add_column("Seconds")
    for name, seconds in sorted(timings.items(), key=lambda item: float(item[1] or 0), reverse=True):
        table.add_row(str(name), str(seconds))
    console.print(table)


def _reliability(data: dict) -> None:
    if not data or data.get("confidence") == "normal":
        return
    _section("Evidence Reliability")
    table = Table(show_lines=True)
    table.add_column("Signal", style="bold")
    table.add_column("Meaning")
    unknown_records = data.get("uncertain_records", []) or []
    if unknown_records:
        table.add_row("Inconclusive DNS records", ", ".join(f"{x.get('record_type')}={x.get('error_type')}" for x in unknown_records[:12]))
    if data.get("mail_unknown"):
        table.add_row("Mail evidence", "Unknown due to lookup timeout/error: " + ", ".join(data.get("mail_unknown", [])))
    if data.get("nameserver_unknown"):
        table.add_row("Nameserver evidence", "Unknown due to resolver timeout/error: " + ", ".join(data.get("nameserver_unknown", [])[:8]))
    if data.get("dnssec_unknown"):
        table.add_row("DNSSEC evidence", "Unknown due to timeout/error; not treated as confirmed misconfiguration")
    if data.get("caa_unknown"):
        table.add_row("CAA evidence", "Unknown due to timeout/error; not treated as confirmed missing CAA")
    table.add_row("Rule", data.get("note", "Unknown values are not scored as confirmed findings."))
    console.print(table)


def _scan_profile(profile: dict) -> None:
    _section("Scan Profile")
    table = Table(show_lines=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key, value in profile.items():
        table.add_row(str(key), _single(value))
    console.print(table)


def _records(records: dict) -> None:
    _section("DNS Records")
    table = Table(show_lines=True)
    table.add_column("Type", style="bold")
    table.add_column("Values")
    table.add_column("TTL")
    table.add_column("Resolver")
    table.add_column("Status")
    ordered = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "SRV", "DS", "DNSKEY"]
    for rtype in ordered + [x for x in records if x not in ordered]:
        item = records.get(rtype, {})
        table.add_row(
            rtype,
            _csv(item.get("values", [])),
            _single(item.get("ttl")),
            _single(item.get("resolver") or item.get("nameserver")),
            item.get("error") or "ok",
        )
    console.print(table)


def _nameservers(ns: dict) -> None:
    _section("Authoritative Nameservers")
    table = Table(show_lines=True)
    table.add_column("Host", style="bold")
    table.add_column("IPv4")
    table.add_column("IPv6")
    table.add_column("Provider")
    table.add_column("Status")
    for item in ns.get("servers", []) or []:
        table.add_row(item.get("host", "-"), _csv(item.get("ipv4", [])), _csv(item.get("ipv6", [])), _single(item.get("provider_hint")), _single(item.get("status")))
    if not ns.get("servers"):
        table.add_row("-", "-", "-", "-", "No nameservers found")
    console.print(table)


def _dns_health(health: dict) -> None:
    _section("DNS Health")
    table = Table(show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Issue")
    table.add_column("Evidence")
    issues = health.get("issues", []) or []
    if not issues:
        table.add_row("OK", "No DNS health issues detected", "-")
    for item in issues:
        table.add_row(_single(item.get("severity")), _single(item.get("title")), _single(item.get("evidence")))
    console.print(table)


def _mail_security(mail: dict) -> None:
    _section("Mail Security")
    table = Table(show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Result")
    table.add_row("MX", _csv(mail.get("mx", []), "Not found"))
    table.add_row("MX providers", _csv(mail.get("mx_providers", [])))
    spf = mail.get("spf", {})
    dmarc = mail.get("dmarc", {})
    dkim = mail.get("dkim", {})
    spf_fallback = "Unknown" if spf.get("status") == "unknown" else ("Skipped" if spf.get("status") == "skipped" else "Not found")
    table.add_row("SPF", _csv(spf.get("records", []), spf_fallback))
    table.add_row("SPF includes", _csv(spf.get("includes", [])))
    table.add_row("SPF lookup estimate", _single(spf.get("dns_lookup_estimate", 0)))
    table.add_row("SPF issues", _csv(spf.get("issues", [])))
    dmarc_fallback = "Unknown" if dmarc.get("status") == "unknown" else ("Skipped" if dmarc.get("status") == "skipped" else "Not found")
    table.add_row("DMARC", _csv(dmarc.get("records", []), dmarc_fallback))
    table.add_row("DMARC policy", _single(dmarc.get("policy")))
    table.add_row("DMARC subdomain policy", _single(dmarc.get("subdomain_policy")))
    table.add_row("DMARC rua", _single(dmarc.get("rua")))
    table.add_row("DKIM selectors checked", _csv(dkim.get("selectors_checked", [])))
    found = [f"{x.get('selector')}: {', '.join(x.get('records', []))}" for x in dkim.get("found", [])]
    table.add_row("DKIM found", _csv(found, "No common selectors found"))
    def opt_mail(label: str, key: str) -> None:
        item = mail.get(key, {})
        if item.get("status") == "unknown":
            fallback = "Unknown"
        elif item.get("status") == "skipped" or item.get("checked") is False:
            fallback = "Skipped"
        else:
            fallback = "Not found"
        table.add_row(label, _csv(item.get("records", []), fallback))
    opt_mail("MTA-STS", "mta_sts")
    opt_mail("TLS-RPT", "tls_rpt")
    opt_mail("BIMI", "bimi")
    console.print(table)


def _dnssec(dnssec: dict) -> None:
    _section("DNSSEC")
    table = Table(show_lines=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Status", _single(dnssec.get("status", "unknown")))
    table.add_row("Appears enabled", _single(dnssec.get("appears_enabled")))
    table.add_row("State", _single(dnssec.get("state")))
    table.add_row("DS", _csv(dnssec.get("ds_records", [])))
    table.add_row("DNSKEY", _csv(dnssec.get("dnskey_records", [])))
    algos = [f"{a.get('algorithm')} {a.get('name')} weak={a.get('weak')}" for a in dnssec.get("algorithms", [])]
    table.add_row("Algorithms", _csv(algos))
    console.print(table)


def _caa(caa: dict) -> None:
    _section("CAA / Certificate Authority Authorization")
    table = Table(show_lines=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Status", _single(caa.get("status", "unknown")))
    table.add_row("Found", _single(caa.get("found")))
    caa_fallback = "Unknown" if caa.get("status") == "unknown" else "Not found"
    table.add_row("Records", _csv(caa.get("records", []), caa_fallback))
    table.add_row("issue", _csv(caa.get("issue", [])))
    table.add_row("issuewild", _csv(caa.get("issuewild", [])))
    table.add_row("iodef", _csv(caa.get("iodef", [])))
    console.print(table)


def _service_records(service: dict) -> None:
    _section("Service Discovery Records")
    table = Table(show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("SRV")
    table.add_column("TXT")
    records = service.get("records", []) or []
    if not records:
        table.add_row("-", "No common SRV/TXT service records found", "-")
    for item in records:
        table.add_row(_single(item.get("name")), _csv(item.get("srv", [])), _csv(item.get("txt", [])))
    console.print(table)


def _reverse_dns(items: list[dict]) -> None:
    _section("Reverse DNS")
    table = Table(show_lines=True)
    table.add_column("IP", style="bold")
    table.add_column("PTR")
    table.add_column("Status")
    if not items:
        table.add_row("-", "-", "No IPs to reverse-resolve")
    for item in items:
        table.add_row(_single(item.get("ip")), _csv(item.get("ptr", []), "No PTR"), item.get("error") or "ok")
    console.print(table)


def _wildcard(wildcard: dict) -> None:
    _section("Wildcard DNS")
    table = Table(show_lines=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Detected", _single(wildcard.get("detected")))
    table.add_row("Confidence", _single(wildcard.get("confidence")))
    table.add_row("Wildcard values", _csv(wildcard.get("wildcard_values", [])))
    table.add_row("Attempts", _single(wildcard.get("attempts")))
    if wildcard.get("note"):
        table.add_row("Note", wildcard.get("note"))
    console.print(table)


def _zone_transfer(items: list[dict]) -> None:
    _section("AXFR Zone Transfer")
    table = Table(show_lines=True)
    table.add_column("Nameserver", style="bold")
    table.add_column("IP")
    table.add_column("Vulnerable")
    table.add_column("Status / Sample")
    if not items:
        table.add_row("-", "-", "False", "Not run or no transfer allowed")
    for item in items:
        sample = _csv(item.get("records_sample", []), item.get("error") or "-")
        table.add_row(_single(item.get("nameserver")), _single(item.get("ip")), _single(item.get("vulnerable")), sample)
    console.print(table)


def _subdomains(sub: dict) -> None:
    _section("Subdomain Discovery")
    summary = Table(show_lines=True)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value")
    summary.add_row("Total unique", _single(sub.get("count", 0)))
    summary.add_row("Verified live", _single(sub.get("verified_count", 0)))
    summary.add_row("Verification enabled", _single(sub.get("verification_enabled")))
    summary.add_row("Permutation enabled", _single(sub.get("permutation_enabled")))
    summary.add_row("Recursive depth", _single(sub.get("recursive_depth")))
    summary.add_row("DNS query budget", f"{sub.get('dns_queries_estimated', 0)} / {sub.get('dns_queries_budget', 0)}")
    console.print(summary)

    passive = sub.get("passive", {})
    source_table = Table(title="Subdomain Sources", show_lines=True)
    source_table.add_column("Source", style="bold")
    source_table.add_column("Count")
    source_table.add_column("Status")
    for src in passive.get("sources", []) or []:
        source_table.add_row(_single(src.get("source")), str(len(src.get("subdomains", []))), src.get("error") or "ok")
    active = sub.get("active", []) or []
    perms = sub.get("permutations", []) or []
    rec = sub.get("recursive", []) or []
    source_table.add_row("native-wordlist", str(sum(1 for x in active if x.get("resolved") and not x.get("wildcard_match"))), f"{len(active)} checked")
    source_table.add_row("native-permutations", str(sum(1 for x in perms if x.get("resolved") and not x.get("wildcard_match"))), f"{len(perms)} checked")
    source_table.add_row("native-recursive", str(sum(1 for x in rec if x.get("resolved") and not x.get("wildcard_match"))), f"{len(rec)} checked")
    console.print(source_table)

    names_table = Table(title="Unique Subdomains", show_lines=False)
    names_table.add_column("#")
    names_table.add_column("Name", style="bold")
    names_table.add_column("Sources")
    source_map = sub.get("source_map", {}) or {}
    limited_names, hidden_names = _limit_items(sub.get("unique_subdomains", []) or [], {"scan_profile": {"terminal_limit": sub.get("terminal_limit", 1000)}})
    for idx, name in enumerate(limited_names, start=1):
        names_table.add_row(str(idx), name, _csv(source_map.get(name, [])))
    if not sub.get("unique_subdomains"):
        names_table.add_row("-", "No subdomains discovered", "-")
    console.print(names_table)
    _maybe_hidden(hidden_names, "unique subdomains")

    verified_table = Table(title="Verified Subdomains", show_lines=True)
    verified_table.add_column("Name", style="bold")
    verified_table.add_column("A/AAAA")
    verified_table.add_column("CNAME")
    verified_table.add_column("Sources")
    limited_verified, hidden_verified = _limit_items(sub.get("verified_subdomains", []) or [], {"scan_profile": {"terminal_limit": sub.get("terminal_limit", 1000)}})
    for item in limited_verified:
        verified_table.add_row(_single(item.get("name")), _csv(item.get("addresses", [])), _csv(item.get("cname", [])), _csv(item.get("sources", [])))
    if not sub.get("verified_subdomains"):
        verified_table.add_row("-", "-", "-", "No verified subdomains")
    console.print(verified_table)
    _maybe_hidden(hidden_verified, "verified subdomains")


def _external_tools(data: dict) -> None:
    _section("Optional OSS Tool Adapters")
    table = Table(show_lines=True)
    table.add_column("Tool", style="bold")
    table.add_column("Available")
    table.add_column("Count")
    table.add_column("Seconds")
    table.add_column("Status")
    if not data.get("enabled"):
        table.add_row("-", "False", "0", "-", "Disabled. Use --oss to enable installed adapters.")
    else:
        for src in data.get("sources", []) or []:
            table.add_row(_single(src.get("source")), _single(src.get("available")), _single(src.get("count", 0)), _single(src.get("duration_seconds")), src.get("error") or ("skipped" if src.get("skipped") else "ok"))
    console.print(table)

    diag = data.get("diagnostics", []) or []
    if diag:
        diag_table = Table(title="OSS Diagnostics", show_lines=True)
        diag_table.add_column("Tool", style="bold")
        diag_table.add_column("Status")
        diag_table.add_column("Sample / Summary")
        for item in diag:
            sample = item.get("stdout_sample") or f"rows={item.get('row_count_sample', 0)}"
            diag_table.add_row(_single(item.get("source")), item.get("error") or "ok", str(sample)[:500])
        console.print(diag_table)


def _takeover(takeover: dict) -> None:
    _section("Takeover-Prone CNAME Fingerprints")
    table = Table(show_lines=True)
    table.add_column("Asset", style="bold")
    table.add_column("CNAME")
    table.add_column("Provider")
    table.add_column("Confidence")
    if not takeover.get("candidates"):
        table.add_row("-", "-", "-", "No candidates detected")
    for item in takeover.get("candidates", []) or []:
        table.add_row(_single(item.get("asset")), _single(item.get("cname")), _single(item.get("provider")), _single(item.get("confidence")))
    console.print(table)
    if takeover.get("note"):
        console.print(f"[dim]{takeover.get('note')}[/dim]")


def _http(items: list[dict]) -> None:
    _section("HTTP Probe")
    table = Table(show_lines=True)
    table.add_column("Host", style="bold")
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Title / Server / Error")
    if not items:
        table.add_row("-", "-", "-", "Not enabled")
    for host in items:
        for url in host.get("urls", []) or []:
            detail = " | ".join(x for x in [url.get("title"), url.get("server"), url.get("error")] if x) or "-"
            table.add_row(_single(host.get("host")), _single(url.get("url")), _single(url.get("status_code")), detail)
    console.print(table)


def _tls(items: list[dict]) -> None:
    _section("TLS Inspection")
    table = Table(show_lines=True)
    table.add_column("Host", style="bold")
    table.add_column("OK")
    table.add_column("Expires")
    table.add_column("SAN count")
    table.add_column("Error")
    if not items:
        table.add_row("-", "-", "-", "-", "Not enabled")
    for item in items:
        table.add_row(_single(item.get("host")), _single(item.get("ok")), _single(item.get("expires_in_days")), str(len(item.get("san_domains", []))), _single(item.get("error")))
    console.print(table)


def _resolver_comparison(comparison: dict) -> None:
    _section("Resolver Comparison")
    table = Table(show_lines=True)
    table.add_column("Record", style="bold")
    table.add_column("Variants")
    if not comparison.get("enabled"):
        table.add_row("-", "Not enabled")
    else:
        for diff in comparison.get("differences", []) or []:
            variants = []
            for item in diff.get("variants", []):
                variants.append(f"{', '.join(item.get('resolvers', []))}: {', '.join(item.get('values', [])) or item.get('error_type')}")
            table.add_row(_single(diff.get("record_type")), "\n".join(variants))
        if not comparison.get("differences"):
            table.add_row("OK", f"No differences across {', '.join(comparison.get('resolvers', []))}")
    console.print(table)


def _whois(whois: dict) -> None:
    _section("WHOIS / RDAP")
    table = Table(show_lines=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Source", _single(whois.get("source")))
    table.add_row("Server", _single(whois.get("server")))
    if whois.get("error"):
        table.add_row("Error", whois.get("error"))
    for key, value in (whois.get("summary", {}) or {}).items():
        table.add_row(str(key), _single(value))
    console.print(table)


def _findings(findings: list[dict]) -> None:
    _section("Risk Findings")
    table = Table(show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Confidence")
    table.add_column("Category")
    table.add_column("Finding")
    table.add_column("Evidence")
    table.add_column("Recommendation")
    if not findings:
        table.add_row("OK", "-", "-", "No findings", "-", "-")
    for item in findings:
        table.add_row(
            _single(item.get("severity")),
            _single(item.get("confidence")),
            _single(item.get("category")),
            _single(item.get("title")),
            _single(item.get("evidence")),
            _single(item.get("recommendation")),
        )
    console.print(table)


def _next_steps(result: dict) -> None:
    target = result.get("target", {}).get("domain", "target")
    _section("Operator Notes")
    console.print(f"- Fast check: [bold]dnsRecon {target} --fast[/bold]")
    console.print(f"- Accurate daily scan: [bold]dnsRecon {target} --profile balanced --mode full --timeout 2 --lifetime 5[/bold]")
    console.print(f"- Deep authorized run: [bold]dnsRecon {target} --ultimate --wordlist wordlists/medium.txt --resolver-file resolvers/public.txt[/bold]")
    console.print(f"- Reports are optional: [bold]dnsRecon {target} --report json,md,html,txt,csv,assets[/bold]")
    console.print("- Unknown/time-out evidence is not treated as confirmed missing or exploitable. Re-run with higher timeout before reporting.")
    console.print("- Treat takeover provider fingerprints as leads only; manually verify ownership before reporting.")


# Backwards-compatible name used by older code/tests.
def print_scan_summary(result: dict) -> None:
    print_terminal_report(result)
