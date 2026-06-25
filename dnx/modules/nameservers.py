from __future__ import annotations

from dnx.core.resolver import DnxResolver


def _unknown(result) -> bool:
    return str(result.error_type or "").upper() in {"TIMEOUT", "SERVFAIL", "NO_NAMESERVERS", "ERROR", "REFUSED"}


def analyze_nameservers(domain: str, resolver: DnxResolver) -> dict:
    ns_answer = resolver.resolve(domain, "NS")
    ns_records = ns_answer.values
    hosts = [ns.rstrip(".") for ns in ns_records]
    resolved = resolver.resolve_many(hosts, ["A", "AAAA"], concurrency=max(1, min(len(hosts) * 2, resolver.config.concurrency))) if hosts else {}
    servers = []
    for host in hosts:
        by_type = resolved.get(host, {})
        a_result = by_type.get("A")
        aaaa_result = by_type.get("AAAA")
        ipv4 = a_result.values if a_result else []
        ipv6 = aaaa_result.values if aaaa_result else []
        uncertain = _unknown(a_result) or _unknown(aaaa_result)
        if ipv4 or ipv6:
            status = "ok"
        elif uncertain:
            status = "unknown"
        else:
            status = "unresolved"
        provider = _provider_hint(host)
        errors = [getattr(item, "error", None) for item in (a_result, aaaa_result) if getattr(item, "error", None)]
        error_types = [getattr(item, "error_type", None) for item in (a_result, aaaa_result) if getattr(item, "error_type", None)]
        servers.append({
            "host": host,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "status": status,
            "provider_hint": provider,
            "resolution_error": "; ".join(errors) if errors else None,
            "resolution_error_type": ",".join(sorted(set(error_types))) if error_types else None,
        })
    status = "found" if servers else ("unknown" if _unknown(ns_answer) else "not_found")
    return {"count": len(servers), "servers": servers, "providers": sorted(set(s["provider_hint"] for s in servers if s.get("provider_hint"))), "status": status, "error": ns_answer.error, "error_type": ns_answer.error_type}


def _provider_hint(host: str) -> str | None:
    lower = host.lower()
    hints = {
        "Cloudflare": ["cloudflare.com"],
        "AWS Route53": ["awsdns"],
        "Google Cloud DNS": ["googledomains.com"],
        "Azure DNS": ["azure-dns"],
        "DigitalOcean": ["digitalocean.com"],
        "Namecheap": ["registrar-servers.com"],
        "GoDaddy": ["domaincontrol.com"],
    }
    for provider, markers in hints.items():
        if any(marker in lower for marker in markers):
            return provider
    return None
