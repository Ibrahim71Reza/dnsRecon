from __future__ import annotations

from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver

COMPARE_TYPES = ["A", "AAAA", "NS", "MX", "CAA", "TXT"]


def compare_resolvers(domain: str, resolver_ips: list[str], timeout: float = 4.0, lifetime: float | None = None) -> dict:
    results: dict[str, dict] = {}
    differences: list[dict] = []
    clean_ips = []
    for ip in resolver_ips:
        ip = ip.strip()
        if ip and ip not in clean_ips:
            clean_ips.append(ip)

    for ip in clean_ips:
        cfg = ScanConfig(timeout=timeout, lifetime=lifetime or max(timeout + 2, 6), resolver=ip, retries=1, rate_limit=0)
        resolver = DnxResolver(cfg)
        results[ip] = {}
        for rtype in COMPARE_TYPES:
            answer = resolver.resolve(domain, rtype)
            results[ip][rtype] = answer.to_dict()

    for rtype in COMPARE_TYPES:
        fingerprints = {}
        for ip, data in results.items():
            values = tuple(data.get(rtype, {}).get("values", []))
            error = data.get(rtype, {}).get("error_type")
            fingerprints.setdefault((values, error), []).append(ip)
        if len(fingerprints) > 1:
            differences.append({
                "record_type": rtype,
                "variants": [
                    {"resolvers": ips, "values": list(values), "error_type": error}
                    for (values, error), ips in fingerprints.items()
                ],
            })

    return {"enabled": bool(clean_ips), "resolvers": clean_ips, "records": results, "differences": differences, "difference_count": len(differences)}
