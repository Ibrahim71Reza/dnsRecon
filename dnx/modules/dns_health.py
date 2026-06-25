from __future__ import annotations

from dnx.core.resolver import DnxResolver


def _soa_primary(soa_values: list[str]) -> str | None:
    if not soa_values:
        return None
    parts = soa_values[0].split()
    return parts[0].rstrip(".").lower() if parts else None


def _ttl_value(item: dict) -> int | None:
    ttl = item.get("ttl")
    return ttl if isinstance(ttl, int) else None


def _uncertain(item: dict | None) -> bool:
    return str((item or {}).get("error_type") or "").upper() in {"TIMEOUT", "SERVFAIL", "NO_NAMESERVERS", "ERROR", "REFUSED"}


def analyze_dns_health(domain: str, resolver: DnxResolver, nameservers: dict, records: dict) -> dict:
    issues: list[dict] = []
    ttl_summary: dict[str, int] = {}

    ns_unknown = nameservers.get("status") == "unknown" or _uncertain(records.get("NS"))
    if nameservers.get("count", 0) == 1:
        issues.append({"id": "DNX-DNS-NS-SINGLE", "severity": "MEDIUM", "title": "Single authoritative nameserver", "evidence": "Only one NS record was found."})
    if nameservers.get("count", 0) == 0 and not ns_unknown:
        issues.append({"id": "DNX-DNS-NS-MISSING", "severity": "HIGH", "title": "No authoritative nameservers visible", "evidence": "The NS query returned no usable nameserver records."})

    for ns in nameservers.get("servers", []):
        host = str(ns.get("host") or "").rstrip(".").lower()
        # Only confirmed NXDOMAIN/no-answer style failures should become health issues.
        # Timeout/SERVFAIL/REFUSED evidence is transient and should stay informational/unknown.
        if ns.get("status") == "unresolved":
            sev = "HIGH" if host.endswith("." + domain) or host == domain else "MEDIUM"
            issues.append({"id": "DNX-DNS-NS-UNRESOLVED", "severity": sev, "title": "Nameserver host does not resolve", "evidence": ns.get("host")})

    soa_item = records.get("SOA", {})
    soa = soa_item.get("values", [])
    if not soa and not _uncertain(soa_item):
        issues.append({"id": "DNX-DNS-SOA-MISSING", "severity": "LOW", "title": "SOA record missing or unreachable", "evidence": records.get("SOA", {}).get("error") or "No SOA answer"})
    else:
        primary = _soa_primary(soa)
        ns_hosts = {str(s.get("host") or "").rstrip(".").lower() for s in nameservers.get("servers", [])}
        if primary and ns_hosts and primary not in ns_hosts:
            issues.append({"id": "DNX-DNS-SOA-NS-MISMATCH", "severity": "INFO", "title": "SOA primary is not listed in NS set", "evidence": f"SOA primary {primary}; NS set {', '.join(sorted(ns_hosts))}"})

    cname_values = records.get("CNAME", {}).get("values", []) or []
    if cname_values and any(records.get(rtype, {}).get("values") for rtype in ["A", "AAAA", "MX", "NS", "TXT"]):
        issues.append({"id": "DNX-DNS-CNAME-CONFLICT", "severity": "HIGH", "title": "CNAME coexists with other apex records", "evidence": "A CNAME answer was seen together with other record types; manually validate DNS correctness."})

    for rtype, item in records.items():
        ttl = _ttl_value(item)
        if ttl is None:
            continue
        ttl_summary[rtype] = ttl
        if ttl < 60 and item.get("values"):
            issues.append({"id": "DNX-DNS-TTL-LOW", "severity": "INFO", "title": f"Very low {rtype} TTL", "evidence": f"{rtype} TTL is {ttl}s; this can increase resolver load and indicate ongoing migration."})
        elif ttl > 86400 and rtype in {"A", "AAAA", "CNAME", "MX"} and item.get("values"):
            issues.append({"id": "DNX-DNS-TTL-HIGH", "severity": "INFO", "title": f"High {rtype} TTL", "evidence": f"{rtype} TTL is {ttl}s; emergency changes may propagate slowly."})

    txt_count = len(records.get("TXT", {}).get("values", []) or [])
    if txt_count > 25:
        issues.append({"id": "DNX-DNS-TXT-MANY", "severity": "INFO", "title": "Large number of TXT records", "evidence": f"{txt_count} TXT records found; review for stale verification tokens."})

    return {"issues": issues, "issue_count": len(issues), "ttl_summary": ttl_summary}
