from __future__ import annotations

from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver

COMMON_SRV_NAMES = [
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_autodiscover._tcp",
    "_ldap._tcp",
    "_ldaps._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_caldav._tcp",
    "_caldavs._tcp",
    "_carddav._tcp",
    "_carddavs._tcp",
    "_matrix._tcp",
    "_minecraft._tcp",
]


def analyze_service_records(domain: str, resolver: DnxResolver, config: ScanConfig) -> dict:
    """Probe common SRV/SVC discovery labels in a bounded way.

    This is DNS-only service discovery. It does not connect to the advertised
    services; it only records published DNS evidence that helps a tester decide
    which assets deserve authorized follow-up.
    """
    names = [f"{prefix}.{domain}" for prefix in COMMON_SRV_NAMES]
    batch = resolver.resolve_many(names, ["SRV", "TXT"], concurrency=min(config.concurrency, 50))
    discovered: list[dict] = []
    for name in names:
        by_type = batch.get(name, {})
        srv = by_type.get("SRV")
        txt = by_type.get("TXT")
        if (srv and srv.values) or (txt and txt.values):
            discovered.append({
                "name": name,
                "srv": srv.values if srv else [],
                "txt": txt.values if txt else [],
                "evidence": {rtype: answer.to_dict() for rtype, answer in by_type.items()},
            })
    return {
        "enabled": True,
        "checked": names,
        "count": len(discovered),
        "records": discovered,
    }
