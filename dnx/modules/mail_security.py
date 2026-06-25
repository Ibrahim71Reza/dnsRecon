from __future__ import annotations

import re
from dataclasses import dataclass

from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver

SPF_RE = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)
DMARC_RE = re.compile(r"^v=DMARC1(?:\s|;|$)", re.IGNORECASE)
DKIM_RE = re.compile(r"^v=DKIM1(?:\s|;|$)", re.IGNORECASE)
BIMI_RE = re.compile(r"^v=BIMI1(?:\s|;|$)", re.IGNORECASE)
TLSRPT_RE = re.compile(r"^v=TLSRPTv1(?:\s|;|$)", re.IGNORECASE)
MTASTS_RE = re.compile(r"^v=STSv1(?:\s|;|$)", re.IGNORECASE)


@dataclass(frozen=True)
class SPFParsed:
    mechanisms: list[str]
    modifiers: dict[str, str]
    includes: list[str]
    redirects: list[str]
    ip4: list[str]
    ip6: list[str]
    all: str | None
    dns_lookup_mechanisms: int
    void_lookup_estimate: int
    issues: list[str]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _txt_values(resolver: DnxResolver, name: str) -> list[str]:
    return [v.strip('"') for v in resolver.resolve_values(name, "TXT")]


def _extract_policy(txt_values: list[str], key: str) -> str | None:
    for txt in txt_values:
        for part in txt.split(";"):
            part = part.strip()
            if part.lower().startswith(key.lower() + "="):
                return part.split("=", 1)[1].strip()
    return None


def _tags(txt_values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for txt in txt_values:
        for part in txt.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                out[key.strip().lower()] = value.strip()
    return out


def parse_spf(record: str) -> SPFParsed:
    tokens = record.split()[1:] if SPF_RE.search(record) else record.split()
    mechanisms: list[str] = []
    modifiers: dict[str, str] = {}
    includes: list[str] = []
    redirects: list[str] = []
    ip4: list[str] = []
    ip6: list[str] = []
    all_mechanism: str | None = None
    issues: list[str] = []
    lookup_mechs = 0
    void_estimate = 0

    for token in tokens:
        token = token.strip()
        if not token:
            continue
        qualifier = token[0] if token[0] in "+-~?" else ""
        body = token[1:] if qualifier else token
        lower = body.lower()
        if "=" in lower and not lower.startswith("ip4:") and not lower.startswith("ip6:"):
            key, value = body.split("=", 1)
            modifiers[key.lower()] = value
            if key.lower() == "redirect":
                redirects.append(value)
                lookup_mechs += 1
            continue
        mechanisms.append(token)
        if lower.startswith("include:"):
            includes.append(body.split(":", 1)[1])
            lookup_mechs += 1
        elif lower.startswith("a") and (lower == "a" or lower.startswith("a:") or lower.startswith("a/")):
            lookup_mechs += 1
        elif lower.startswith("mx") and (lower == "mx" or lower.startswith("mx:") or lower.startswith("mx/")):
            lookup_mechs += 1
        elif lower.startswith("ptr"):
            lookup_mechs += 1
            issues.append("ptr mechanism is discouraged because it is slow and unreliable")
        elif lower.startswith("exists:"):
            lookup_mechs += 1
        elif lower.startswith("ip4:"):
            ip4.append(body.split(":", 1)[1])
        elif lower.startswith("ip6:"):
            ip6.append(body.split(":", 1)[1])
        elif lower == "all":
            all_mechanism = qualifier + "all" if qualifier else "+all"
    if lookup_mechs > 10:
        issues.append("SPF policy exceeds the 10 DNS-lookup limit")
    elif lookup_mechs >= 8:
        issues.append("SPF policy is close to the 10 DNS-lookup limit")
    if all_mechanism in {"+all", "?all"}:
        issues.append("SPF all mechanism is permissive")
    return SPFParsed(mechanisms, modifiers, sorted(set(includes)), sorted(set(redirects)), ip4, ip6, all_mechanism, lookup_mechs, void_estimate, issues)


def _extract_includes(spf_records: list[str]) -> list[str]:
    includes: list[str] = []
    for record in spf_records:
        includes.extend(re.findall(r"include:([^\s]+)", record, flags=re.IGNORECASE))
    return sorted(set(includes))


def _mx_provider(mx: list[str]) -> list[str]:
    providers: set[str] = set()
    joined = " ".join(mx).lower()
    hints = {
        "Google Workspace": ["google.com", "googlemail.com", "aspmx.l.google.com"],
        "Microsoft 365": ["protection.outlook.com", "outlook.com"],
        "Zoho": ["zoho.com", "zohomail"],
        "Proton Mail": ["protonmail", "protonmail.ch"],
        "Fastmail": ["messagingengine.com"],
        "Amazon SES": ["amazonses.com"],
        "Mailgun": ["mailgun.org"],
        "SendGrid": ["sendgrid.net"],
    }
    for provider, needles in hints.items():
        if any(needle in joined for needle in needles):
            providers.add(provider)
    return sorted(providers)


def _result_status(result) -> tuple[str, str | None, str | None]:
    """Return found/not_found/unknown for a DNS QueryResult-like object."""
    if result is None:
        return "unknown", "missing_result", "ERROR"
    if getattr(result, "values", None):
        return "found", None, getattr(result, "error_type", None)
    error_type = str(getattr(result, "error_type", "") or "").upper()
    error = getattr(result, "error", None)
    if error_type in {"NO_ANSWER", "NXDOMAIN", "OK"}:
        return "not_found", error, error_type
    return "unknown", error, error_type


def analyze_mail_security(domain: str, resolver: DnxResolver, config: ScanConfig) -> dict:
    mx_result = resolver.resolve(domain, "MX")
    mx = mx_result.values
    mx_status, mx_error, mx_error_type = _result_status(mx_result)

    dmarc_name = f"_dmarc.{domain}"
    mta_sts_name = f"_mta-sts.{domain}"
    tlsrpt_name = f"_smtp._tls.{domain}"
    bimi_name = f"default._bimi.{domain}"
    dkim_names = [f"{selector}._domainkey.{domain}" for selector in config.dkim_selectors]
    if config.profile == "quick":
        # Quick profile checks only apex TXT/SPF and DMARC.  Negative sweeps for
        # MTA-STS/TLS-RPT/BIMI/DKIM are intentionally skipped because they can
        # dominate runtime and create misleading timeout-based findings.
        txt_names = [domain, dmarc_name]
    else:
        txt_names = [domain, dmarc_name, mta_sts_name, tlsrpt_name, bimi_name, *dkim_names]
    txt_batch = resolver.resolve_many(txt_names, ["TXT"], concurrency=config.concurrency)

    def result_for(name: str):
        return txt_batch.get(name, {}).get("TXT")

    def txt_for(name: str) -> list[str]:
        item = result_for(name)
        return [v.strip('"') for v in item.values] if item and item.values else []

    root_result = result_for(domain)
    root_status, root_error, root_error_type = _result_status(root_result)
    root_txt = txt_for(domain)
    spf = [txt for txt in root_txt if SPF_RE.search(txt)]
    spf_status = "found" if spf else root_status
    spf_parsed = [parse_spf(record).to_dict() for record in spf]

    dmarc_result = result_for(dmarc_name)
    dmarc_status, dmarc_error, dmarc_error_type = _result_status(dmarc_result)
    dmarc_txt = txt_for(dmarc_name)
    dmarc = [txt for txt in dmarc_txt if DMARC_RE.search(txt)]
    if dmarc:
        dmarc_status = "found"
    dmarc_tags = _tags(dmarc)

    dkim_results = []
    for selector, name in zip(config.dkim_selectors, dkim_names):
        txt = txt_for(name)
        dkim = [value for value in txt if DKIM_RE.search(value)]
        if dkim:
            dkim_results.append({"selector": selector, "name": name, "records": dkim, "tags": _tags(dkim)})

    def optional_txt(name: str, regex) -> dict:
        item = result_for(name)
        status, error, error_type = _result_status(item)
        records = [txt for txt in txt_for(name) if regex.search(txt)]
        if records:
            status = "found"
        return {"name": name, "checked": True, "status": status, "found": bool(records), "records": records, "tags": _tags(records), "error": error, "error_type": error_type}

    if config.profile == "quick":
        mta_sts_obj = {"name": mta_sts_name, "checked": False, "status": "skipped", "found": False, "records": [], "tags": {}, "error": None, "error_type": None}
        tls_rpt_obj = {"name": tlsrpt_name, "checked": False, "status": "skipped", "found": False, "records": [], "tags": {}, "error": None, "error_type": None}
        bimi_obj = {"name": bimi_name, "checked": False, "status": "skipped", "found": False, "records": [], "tags": {}, "error": None, "error_type": None}
    else:
        mta_sts_obj = optional_txt(mta_sts_name, MTASTS_RE)
        tls_rpt_obj = optional_txt(tlsrpt_name, TLSRPT_RE)
        bimi_obj = optional_txt(bimi_name, BIMI_RE)

    return {
        "mx": mx,
        "mx_status": mx_status,
        "mx_error": mx_error,
        "mx_error_type": mx_error_type,
        "mx_providers": _mx_provider(mx),
        "spf": {
            "checked": True,
            "status": spf_status,
            "found": bool(spf),
            "lookup_error": root_error,
            "error_type": root_error_type,
            "records": spf,
            "parsed": spf_parsed,
            "all_mechanism": spf_parsed[0].get("all") if spf_parsed else None,
            "includes": _extract_includes(spf),
            "dns_lookup_estimate": max([p.get("dns_lookup_mechanisms", 0) for p in spf_parsed], default=0),
            "issues": sorted(set(issue for parsed in spf_parsed for issue in parsed.get("issues", []))),
        },
        "dmarc": {
            "checked": True,
            "status": dmarc_status,
            "found": bool(dmarc),
            "lookup_error": dmarc_error,
            "error_type": dmarc_error_type,
            "name": dmarc_name,
            "records": dmarc,
            "tags": dmarc_tags,
            "policy": dmarc_tags.get("p"),
            "subdomain_policy": dmarc_tags.get("sp"),
            "pct": dmarc_tags.get("pct"),
            "rua": dmarc_tags.get("rua"),
            "ruf": dmarc_tags.get("ruf"),
            "adkim": dmarc_tags.get("adkim"),
            "aspf": dmarc_tags.get("aspf"),
        },
        "dkim": {
            "checked": bool(config.dkim_selectors),
            "selectors_checked": config.dkim_selectors,
            "found": dkim_results,
        },
        "mta_sts": mta_sts_obj,
        "tls_rpt": tls_rpt_obj,
        "bimi": bimi_obj,
    }
