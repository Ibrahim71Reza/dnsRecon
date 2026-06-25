from __future__ import annotations

import dns.exception
import dns.query
import dns.zone

from dnx.core.config import ScanConfig


def test_zone_transfer(domain: str, nameservers: dict, config: ScanConfig) -> list[dict]:
    results: list[dict] = []
    if not config.active:
        return results

    for server in nameservers.get("servers", []):
        host = server.get("host")
        ips = list(server.get("ipv4", [])) + list(server.get("ipv6", []))
        if not ips:
            results.append({
                "nameserver": host,
                "ip": None,
                "vulnerable": False,
                "records_sample": [],
                "error": "Nameserver IP could not be resolved",
            })
            continue
        for ip in ips:
            try:
                xfr = dns.query.xfr(where=ip, zone=domain, timeout=config.timeout, lifetime=config.lifetime)
                zone = dns.zone.from_xfr(xfr, relativize=False)
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        records.append(f"{name} {rdataset}")
                        if len(records) >= 25:
                            break
                    if len(records) >= 25:
                        break
                results.append({
                    "nameserver": host,
                    "ip": ip,
                    "vulnerable": True,
                    "records_sample": records,
                    "error": None,
                })
            except dns.exception.FormError:
                results.append({"nameserver": host, "ip": ip, "vulnerable": False, "records_sample": [], "error": "Transfer refused or malformed response"})
            except dns.exception.Timeout:
                results.append({"nameserver": host, "ip": ip, "vulnerable": False, "records_sample": [], "error": "Timeout"})
            except Exception as exc:  # pragma: no cover - network defensive handling
                results.append({"nameserver": host, "ip": ip, "vulnerable": False, "records_sample": [], "error": str(exc)})
    return results
