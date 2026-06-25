from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from dnx import __version__
from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver, ResolverPool, load_resolver_ips
from dnx.core.target import Target
from dnx.findings.engine import analyze_findings
from dnx.findings.score import risk_score
from dnx.modules.basic_records import collect_basic_records
from dnx.modules.caa import analyze_caa
from dnx.modules.dns_health import analyze_dns_health
from dnx.modules.dnssec import analyze_dnssec
from dnx.modules.external_tools import run_external_subdomain_sources
from dnx.modules.http_probe import probe_http_hosts
from dnx.modules.mail_security import analyze_mail_security
from dnx.modules.service_records import analyze_service_records
from dnx.modules.nameservers import analyze_nameservers
from dnx.modules.resolver_compare import compare_resolvers
from dnx.modules.reverse_dns import reverse_lookup
from dnx.modules.subdomains import discover_subdomains
from dnx.modules.takeover import analyze_takeover_candidates
from dnx.modules.tls_inspect import inspect_tls_hosts
from dnx.modules.whois_lookup import whois_summary
from dnx.modules.wildcard import detect_wildcard
from dnx.modules.zone_transfer import test_zone_transfer

Mode = Literal["full", "passive", "active", "safe"]


def build_config(
    mode: Mode = "full",
    resolver: str | None = None,
    output_dir: Path = Path("reports"),
    wordlist: Path | None = None,
    timeout: float = 2.0,
    lifetime: float | None = None,
    verify_subdomains: bool = False,
    max_verify: int = 300,
    retries: int = 1,
    compare_resolvers_value: str | None = None,
    verbose: bool = False,
    whois: bool = True,
    rdap: bool = True,
    redact_whois: bool = True,
    concurrency: int = 50,
    rate_limit: float = 0.0,
    resolver_file: Path | None = None,
    profile: str = "balanced",
    recursive_depth: int = 0,
    permutations: bool = False,
    max_dns_queries: int = 25_000,
    http_probe: bool = False,
    tls_probe: bool = False,
    scope_file: Path | None = None,
    exclude_file: Path | None = None,
    axfr: bool = True,
    export_assets: bool = True,
    terminal_full: bool = True,
    report_formats: list[str] | None = None,
    use_external_tools: bool = False,
    external_tools_value: str | None = None,
    external_tool_timeout: float = 25.0,
    terminal_limit: int = 1000,
    external_candidate_limit: int = 50_000,
    gotator_depth: int = 2,
    gotator_numbers: int = 3,
    nuclei_templates_value: str | None = None,
    fast_mode: bool = False,
) -> ScanConfig:
    compare_resolvers_list = []
    external_tools = [item.strip().lower() for item in (external_tools_value or "auto").split(",") if item.strip()]
    nuclei_templates = [item.strip() for item in (nuclei_templates_value or "").split(",") if item.strip()]
    if compare_resolvers_value:
        compare_resolvers_list = [item.strip() for item in compare_resolvers_value.split(",") if item.strip()]
    if resolver_file:
        compare_resolvers_list.extend(ip for ip in load_resolver_ips(resolver_file) if ip not in compare_resolvers_list)

    if profile == "quick":
        verify_subdomains = False
        permutations = False
        http_probe = False
        tls_probe = False
        # Quick profile is for responsive terminal feedback. Do not brute-force
        # the built-in default wordlist unless the user explicitly provides a
        # wordlist. This prevents surprising 20-60s scans on slow networks.
        max_dns_queries = min(max_dns_queries, 300) if wordlist else 0
        concurrency = min(concurrency, 30)
    elif profile == "deep":
        verify_subdomains = True
        permutations = True
        max_verify = max(max_verify, 1000)
        max_dns_queries = max(max_dns_queries, 75_000)
        concurrency = max(concurrency, 80)
    elif profile == "report":
        verify_subdomains = True
        http_probe = True
        tls_probe = True
        max_verify = max(max_verify, 500)

    effective_lifetime = lifetime if lifetime is not None else (2.0 if profile == "quick" else max(timeout * 2.0, timeout + 1, 4))
    if profile == "quick":
        # Quick/default scans must stay responsive.  They should not spend
        # time on high-cost checks unless the user explicitly selects a
        # balanced/deep profile or a specific mode.
        whois = False
        rdap = False
        axfr = False

    config = ScanConfig(
        timeout=timeout,
        lifetime=effective_lifetime,
        resolver=resolver,
        resolver_file=resolver_file,
        output_dir=output_dir,
        wordlist=wordlist,
        verify_subdomains=verify_subdomains,
        max_verify=max_verify,
        retries=retries,
        compare_resolvers=compare_resolvers_list,
        verbose=verbose,
        whois=whois,
        rdap=rdap,
        redact_whois=redact_whois,
        concurrency=concurrency,
        rate_limit=rate_limit,
        profile=profile,
        recursive_depth=recursive_depth,
        permutations=permutations,
        max_dns_queries=max_dns_queries,
        http_probe=http_probe,
        tls_probe=tls_probe,
        scope_file=scope_file,
        exclude_file=exclude_file,
        axfr=axfr,
        export_assets=export_assets,
        terminal_full=terminal_full,
        report_formats=report_formats or [],
        use_external_tools=use_external_tools,
        external_tools=external_tools or ["auto"],
        external_tool_timeout=external_tool_timeout,
        terminal_limit=terminal_limit,
        external_candidate_limit=external_candidate_limit,
        gotator_depth=gotator_depth,
        gotator_numbers=gotator_numbers,
        nuclei_templates=nuclei_templates,
        fast_mode=fast_mode,
    )
    if profile == "quick":
        # Keep quick output useful but avoid slow negative DNS lookups.
        # Balanced/deep profiles still query the full modern DNS record set.
        quick_records = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY", "HTTPS"]
        config.record_types = quick_records
        config.dkim_selectors = []

    if mode == "passive":
        config.active = False
        config.brute_force = False
        config.passive = True
        config.ct_logs = True
        config.http_probe = False if not http_probe else http_probe
        config.tls_probe = False if not tls_probe else tls_probe
    elif mode == "active":
        config.active = True
        config.brute_force = True
        config.passive = False
        config.ct_logs = False
    elif mode == "safe":
        config.active = False
        config.brute_force = False
        config.passive = True
        config.ct_logs = True
        config.http_probe = False
        config.tls_probe = False
    else:
        config.active = True
        config.brute_force = True
        config.passive = True
        config.ct_logs = True

    if profile == "quick" and mode == "full":
        # Defensive guard for API callers: quick should not spend time on
        # public passive APIs unless passive mode was explicitly selected.
        config.passive = False
        config.ct_logs = False

    return config


def _merge_external_subdomains(result: dict, external: dict, resolver: DnxResolver, config: ScanConfig) -> None:
    """Merge normalized optional OSS-tool output into dnsRecon canonical subdomain object."""
    sub = result.setdefault("subdomains", {})
    names = {str(x).strip().lower().strip(".") for x in sub.get("unique_subdomains", []) if str(x).strip()}
    ext_names = {str(x).strip().lower().strip(".") for x in external.get("subdomains", []) if str(x).strip()}
    if not ext_names:
        sub["count"] = len(names)
        return

    source_map = {name: set(srcs) for name, srcs in (sub.get("source_map", {}) or {}).items()}
    for name, srcs in (external.get("source_map", {}) or {}).items():
        if name in ext_names:
            source_map.setdefault(name, set()).update(f"oss:{src}" for src in srcs)

    names.update(ext_names)
    sub["unique_subdomains"] = sorted(names)
    sub["count"] = len(names)
    sub["source_map"] = {name: sorted(srcs) for name, srcs in sorted(source_map.items())}

    if not config.verify_subdomains:
        return

    already_verified = {item.get("name") for item in sub.get("verified_subdomains", []) or []}
    to_verify = sorted(ext_names - already_verified)[: max(0, config.max_verify - len(already_verified))]
    if not to_verify:
        return
    batch = resolver.resolve_many(to_verify, ["A", "AAAA", "CNAME"], concurrency=config.concurrency)
    new_verified = []
    wildcard_values = set(result.get("wildcard", {}).get("wildcard_values", []) or [])
    for name, by_type in batch.items():
        a = by_type.get("A")
        aaaa = by_type.get("AAAA")
        cname = by_type.get("CNAME")
        addresses = sorted(set((a.values if a else []) + (aaaa.values if aaaa else [])))
        cnames = cname.values if cname else []
        wildcard_match = bool(wildcard_values and addresses and set(addresses).issubset(wildcard_values))
        if addresses or cnames:
            if not wildcard_match:
                new_verified.append({
                    "name": name,
                    "addresses": addresses,
                    "cname": cnames,
                    "resolved": True,
                    "wildcard_match": False,
                    "sources": sorted(source_map.get(name, [])),
                    "evidence": {rtype: answer.to_dict() for rtype, answer in by_type.items()},
                })
    sub.setdefault("verified_subdomains", []).extend(new_verified)
    # De-duplicate by name after merging native and external evidence.
    dedup = {item.get("name"): item for item in sub.get("verified_subdomains", []) if item.get("name")}
    sub["verified_subdomains"] = [dedup[name] for name in sorted(dedup)]
    sub["verified_count"] = len(sub["verified_subdomains"])


def _is_uncertain_error(error_type: str | None) -> bool:
    return str(error_type or "").upper() in {"TIMEOUT", "SERVFAIL", "NO_NAMESERVERS", "ERROR", "REFUSED"}


def _assess_reliability(result: dict) -> dict:
    """Summarize inconclusive DNS evidence so reports do not overclaim.

    v1.0.3 treats DNS timeouts and transient resolver failures as UNKNOWN, not
    as proof that records are missing or misconfigured.  This is especially
    important in quick/default scans with aggressive timeouts.
    """
    uncertain_records = []
    for rtype, item in (result.get("records") or {}).items():
        if _is_uncertain_error(item.get("error_type")):
            uncertain_records.append({"name": item.get("name"), "record_type": rtype, "error_type": item.get("error_type"), "error": item.get("error")})

    mail = result.get("mail_security") or {}
    mail_unknown = []
    for key in ["mx_status", "spf", "dmarc", "mta_sts", "tls_rpt", "bimi"]:
        item = mail.get(key) if key != "mx_status" else {"status": mail.get("mx_status"), "error": mail.get("mx_error")}
        if isinstance(item, dict) and item.get("status") == "unknown":
            mail_unknown.append(key)

    dnssec = result.get("dnssec") or {}
    caa = result.get("caa") or {}
    ns_unknown = [s.get("host") for s in (result.get("nameservers") or {}).get("servers", []) if s.get("status") == "unknown"]
    return {
        "confidence": "limited" if uncertain_records or mail_unknown or ns_unknown or dnssec.get("status") == "unknown" or caa.get("status") == "unknown" else "normal",
        "uncertain_records": uncertain_records,
        "mail_unknown": mail_unknown,
        "nameserver_unknown": ns_unknown,
        "dnssec_unknown": bool(dnssec.get("status") == "unknown"),
        "caa_unknown": bool(caa.get("status") == "unknown"),
        "note": "Timeouts and transient DNS errors are reported as unknown, not as confirmed missing records."
    }


def run_scan(target: Target, config: ScanConfig, mode: str = "full") -> dict:
    started = time.perf_counter()
    resolver_pool = ResolverPool(config)
    resolver: DnxResolver = resolver_pool.first()
    domain = target.domain

    result: dict = {
        "tool": "dnsRecon",
        "schema_version": "1.0",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": {"original": target.original, "domain": domain},
        "scan_profile": {
            "profile": config.profile,
            "active_checks": config.active,
            "passive_checks": config.passive,
            "bruteforce": config.brute_force,
            "verify_subdomains": config.verify_subdomains,
            "permutations": config.permutations,
            "recursive_depth": config.recursive_depth,
            "timeout": config.timeout,
            "lifetime": config.lifetime,
            "retries": config.retries,
            "concurrency": config.concurrency,
            "rate_limit": config.rate_limit,
            "max_dns_queries": config.max_dns_queries,
            "whois": config.whois,
            "rdap": config.rdap,
            "redact_whois": config.redact_whois,
            "http_probe": config.http_probe,
            "tls_probe": config.tls_probe,
            "axfr": config.axfr,
            "export_assets": config.export_assets,
            "resolver": config.resolver,
            "effective_resolvers": resolver.nameservers,
            "compare_resolvers": config.compare_resolvers,
            "terminal_limit": config.terminal_limit,
            "use_external_tools": config.use_external_tools,
            "external_tools": config.external_tools,
            "external_candidate_limit": config.external_candidate_limit,
            "fast_mode": config.fast_mode,
        },
        "resolver_health": [],
        "records": {},
        "nameservers": {},
        "dns_health": {},
        "mail_security": {},
        "dnssec": {},
        "caa": {},
        "service_records": {},
        "reverse_dns": [],
        "wildcard": {},
        "zone_transfer": [],
        "subdomains": {},
        "takeover": {},
        "external_tools": {},
        "http": [],
        "tls": [],
        "resolver_comparison": {},
        "whois": {},
        "findings": [],
        "risk": {},
        "duration_seconds": None,
        "module_timings": {},
    }

    def timed(name: str, fn):
        module_started = time.perf_counter()
        try:
            return fn()
        finally:
            result["module_timings"][name] = round(time.perf_counter() - module_started, 3)

    # Independent DNS intelligence modules run concurrently so quick scans do
    # not feel like a serial chain of timeouts on slow networks. The resolver is
    # already used concurrently by resolve_many(), and its cache is guarded.
    parallel_modules = {
        "records": ("dns_records", lambda: collect_basic_records(domain, resolver, config)),
        "nameservers": ("nameservers", lambda: analyze_nameservers(domain, resolver)),
        "mail_security": ("mail_security", lambda: analyze_mail_security(domain, resolver, config)),
        "dnssec": ("dnssec", lambda: analyze_dnssec(domain, resolver)),
        "caa": ("caa", lambda: analyze_caa(domain, resolver)),
    }
    with ThreadPoolExecutor(max_workers=len(parallel_modules)) as executor:
        future_map = {executor.submit(timed, timing_name, fn): result_key for result_key, (timing_name, fn) in parallel_modules.items()}
        for future in as_completed(future_map):
            result[future_map[future]] = future.result()

    result["dns_health"] = timed("dns_health", lambda: analyze_dns_health(domain, resolver, result["nameservers"], result["records"]))
    if config.fast_mode or config.profile == "quick":
        note = "Skipped by --fast." if config.fast_mode else "Skipped in quick profile."
        result["service_records"] = {"enabled": False, "checked": [], "count": 0, "records": [], "note": note}
    else:
        result["service_records"] = timed("service_records", lambda: analyze_service_records(domain, resolver, config))

    ips: list[str] = []
    ips.extend(result["records"].get("A", {}).get("values", []))
    ips.extend(result["records"].get("AAAA", {}).get("values", []))
    if not (config.fast_mode or config.profile == "quick"):
        for ns in result["nameservers"].get("servers", []):
            ips.extend(ns.get("ipv4", []))
            ips.extend(ns.get("ipv6", []))
    else:
        ips = ips[:4]
    result["reverse_dns"] = timed("reverse_dns", lambda: reverse_lookup(ips, resolver))

    if config.active and not (config.fast_mode or config.profile == "quick"):
        result["wildcard"] = timed("wildcard", lambda: detect_wildcard(domain, resolver))
        result["zone_transfer"] = timed("zone_transfer", lambda: test_zone_transfer(domain, result["nameservers"], config)) if config.axfr else []
    else:
        if config.fast_mode:
            note = "Skipped by --fast."
        elif config.profile == "quick":
            note = "Skipped in quick profile."
        else:
            note = "Skipped because active checks are disabled."
        result["wildcard"] = {"detected": False, "tests": [], "wildcard_values": [], "note": note}
        result["zone_transfer"] = []

    result["subdomains"] = timed("subdomains", lambda: discover_subdomains(domain, resolver, config, result["wildcard"]))
    result["subdomains"]["terminal_limit"] = config.terminal_limit
    result["external_tools"] = timed("external_tools", lambda: run_external_subdomain_sources(domain, config))
    _merge_external_subdomains(result, result["external_tools"], resolver, config)
    result["subdomains"]["terminal_limit"] = config.terminal_limit
    result["takeover"] = timed("takeover", lambda: analyze_takeover_candidates(result)) if config.takeover_check else {"enabled": False, "candidates": [], "count": 0}

    hosts_for_probe = [domain]
    hosts_for_probe.extend(result["subdomains"].get("unique_subdomains", [])[: max(config.max_verify, 100)])
    if config.http_probe:
        result["http"] = timed("http_probe", lambda: probe_http_hosts(hosts_for_probe, timeout=config.timeout, concurrency=config.concurrency, limit=max(config.max_verify, 100)))
    if config.tls_probe:
        result["tls"] = timed("tls_probe", lambda: inspect_tls_hosts(hosts_for_probe, timeout=config.timeout, concurrency=config.concurrency, limit=max(config.max_verify, 100)))

    if config.whois:
        result["whois"] = timed("whois", lambda: whois_summary(domain, timeout=config.timeout, prefer_rdap=config.rdap, redact=config.redact_whois))
    else:
        result["whois"] = {"source": "disabled", "server": None, "summary": {}, "raw_sample": "", "error": "disabled"}

    if config.compare_resolvers:
        result["resolver_comparison"] = timed("resolver_comparison", lambda: compare_resolvers(domain, config.compare_resolvers, timeout=config.timeout, lifetime=config.lifetime))
    else:
        result["resolver_comparison"] = {"enabled": False, "resolvers": [], "records": {}, "differences": [], "difference_count": 0}

    result["reliability"] = _assess_reliability(result)

    if config.verbose:
        result["resolver_health"] = timed("resolver_health", lambda: resolver_pool.health(domain))

    result["findings"] = timed("findings", lambda: analyze_findings(result))
    result["risk"] = timed("risk", lambda: risk_score(result["findings"]))
    result["duration_seconds"] = round(time.perf_counter() - started, 3)
    return result
