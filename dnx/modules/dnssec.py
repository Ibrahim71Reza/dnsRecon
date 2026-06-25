from __future__ import annotations

import re

from dnx.core.resolver import DnxResolver


ALGO_NAMES = {
    "5": "RSASHA1",
    "7": "RSASHA1-NSEC3-SHA1",
    "8": "RSASHA256",
    "10": "RSASHA512",
    "13": "ECDSAP256SHA256",
    "14": "ECDSAP384SHA384",
    "15": "ED25519",
    "16": "ED448",
}
WEAK_ALGOS = {"1", "3", "5", "7"}


def _extract_algorithms(records: list[str]) -> list[dict[str, str]]:
    algos = []
    for rec in records:
        parts = re.split(r"\s+", rec.strip())
        if len(parts) >= 3:
            algo = parts[2] if parts[0].isdigit() and parts[1].isdigit() else None
            if algo and algo.isdigit():
                algos.append({"algorithm": algo, "name": ALGO_NAMES.get(algo, "unknown"), "weak": algo in WEAK_ALGOS, "record": rec})
    return algos


def _uncertain(result) -> bool:
    return result is not None and str(result.error_type or "").upper() in {"TIMEOUT", "SERVFAIL", "NO_NAMESERVERS", "ERROR", "REFUSED"}


def analyze_dnssec(domain: str, resolver: DnxResolver) -> dict:
    batch = resolver.resolve_many([domain], ["DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3PARAM"], concurrency=5).get(domain, {})
    ds_result = batch.get("DS")
    dnskey_result = batch.get("DNSKEY")
    rrsig_result = batch.get("RRSIG")
    ds = ds_result.values if ds_result else []
    dnskey = dnskey_result.values if dnskey_result else []
    rrsig = rrsig_result.values if rrsig_result else []
    nsec = batch.get("NSEC").values if batch.get("NSEC") else []
    nsec3 = batch.get("NSEC3PARAM").values if batch.get("NSEC3PARAM") else []

    critical_unknown = any(_uncertain(item) for item in [ds_result, dnskey_result, rrsig_result])
    appears_enabled = bool(ds or dnskey or rrsig)
    if critical_unknown:
        status = "unknown"
        if appears_enabled:
            state = "inconclusive_dnssec_timeout_with_partial_evidence"
        else:
            state = "unknown_timeout"
    else:
        status = "found" if appears_enabled else "not_found"
        if ds and dnskey:
            state = "signed_with_parent_ds"
        elif dnskey and not ds:
            state = "child_signed_no_parent_ds"
        elif ds and not dnskey:
            state = "parent_ds_but_child_key_missing_or_unreachable"
        else:
            state = "unsigned_or_not_detected"
    algorithms = _extract_algorithms(dnskey + ds)
    return {
        "status": status,
        "inconclusive": status == "unknown",
        "ds_records": ds,
        "dnskey_records": dnskey,
        "rrsig_records": rrsig,
        "nsec_records": nsec,
        "nsec3param_records": nsec3,
        "appears_enabled": appears_enabled,
        "state": state,
        "algorithms": algorithms,
        "weak_algorithms": [a for a in algorithms if a.get("weak")],
        "evidence": {rtype: result.to_dict() for rtype, result in batch.items()},
    }
