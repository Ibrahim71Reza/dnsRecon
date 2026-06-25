from __future__ import annotations

import ipaddress

import dns.reversename

from dnx.core.resolver import DnxResolver


def reverse_lookup(ips: list[str], resolver: DnxResolver) -> list[dict]:
    results = []
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        try:
            ipaddress.ip_address(ip)
            ptr_name = dns.reversename.from_address(ip).to_text()
            answer = resolver.resolve(ptr_name, "PTR")
            results.append({"ip": ip, "ptr": [v.rstrip(".") for v in answer.values], "error": answer.error, "evidence": answer.to_dict()})
        except Exception as exc:  # pragma: no cover - network and parser defensive handling
            results.append({"ip": ip, "ptr": [], "error": str(exc)})
    return results
