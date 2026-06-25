from __future__ import annotations

from dnx.findings.severity import sort_findings
from dnx.modules.takeover import fingerprint_provider


def finding(severity: str, title: str, evidence: str, recommendation: str, confidence: str = "medium", *, fid: str | None = None, category: str = "General", affected_assets: list[str] | None = None) -> dict:
    return {
        "id": fid or title.upper().replace(" ", "_")[:48],
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        "category": category,
        "affected_assets": affected_assets or [],
    }


def _record_uncertain(item: dict | None) -> bool:
    return str((item or {}).get("error_type") or "").upper() in {"TIMEOUT", "SERVFAIL", "NO_NAMESERVERS", "ERROR", "REFUSED"}


def _status_is_not_found(item: dict | None) -> bool:
    # Backward-compatible: older tests/JSON may only have found=False.
    return isinstance(item, dict) and (item.get("status") == "not_found" or ("status" not in item and item.get("found") is False))


def _status_is_unknown(item: dict | None) -> bool:
    return isinstance(item, dict) and item.get("status") == "unknown"


def analyze_findings(result: dict) -> list[dict]:
    findings: list[dict] = []
    records = result.get("records", {})
    mail = result.get("mail_security", {})
    quick_profile = result.get("scan_profile", {}).get("profile") == "quick"
    dnssec = result.get("dnssec", {})
    caa = result.get("caa", {})
    zone = result.get("zone_transfer", [])
    wildcard = result.get("wildcard", {})
    ns = result.get("nameservers", {})
    subdomains = result.get("subdomains", {})
    resolver_comparison = result.get("resolver_comparison", {})
    dns_health = result.get("dns_health", {})
    takeover = result.get("takeover", {})
    tls = result.get("tls", [])
    http = result.get("http", [])

    domain = result.get("target", {}).get("domain", "<domain>")

    a_rec = records.get("A", {})
    aaaa_rec = records.get("AAAA", {})
    if not a_rec.get("values") and not aaaa_rec.get("values") and not (_record_uncertain(a_rec) or _record_uncertain(aaaa_rec)):
        findings.append(finding("INFO", "No apex A/AAAA record found", "The root domain did not return IPv4 or IPv6 address records.", "Verify whether the apex domain is intentionally not serving traffic.", "high", fid="DNX-DNS-001", category="DNS"))

    ns_unknown = ns.get("status") == "unknown" or _record_uncertain(records.get("NS", {}))
    if ns.get("count", 0) == 0 and not ns_unknown:
        findings.append(finding("HIGH", "No nameserver records found", "No NS records were discovered for the target domain.", "Confirm the domain is valid and properly delegated.", "high", fid="DNX-DNS-002", category="DNS"))
    else:
        unresolved = [s["host"] for s in ns.get("servers", []) if s.get("status") == "unresolved"]
        unknown_ns = [s["host"] for s in ns.get("servers", []) if s.get("status") == "unknown"]
        if unresolved:
            findings.append(finding("MEDIUM", "Some nameservers did not resolve", ", ".join(unresolved), "Check nameserver glue and DNS hosting configuration.", "high", fid="DNX-DNS-003", category="DNS", affected_assets=unresolved))
        if unknown_ns:
            findings.append(finding("INFO", "Nameserver resolution unknown", ", ".join(unknown_ns), "Retry with a larger --timeout/--lifetime or a different resolver before reporting nameserver glue issues.", "low", fid="DNX-DNS-003U", category="DNS", affected_assets=unknown_ns))

    for issue in dns_health.get("issues", []):
        findings.append(finding(issue.get("severity", "INFO"), issue.get("title", "DNS health issue"), str(issue.get("evidence", "")), "Review DNS delegation and authoritative DNS hosting configuration.", "medium", fid=issue.get("id"), category="DNS"))

    if not mail.get("mx") and mail.get("mx_status") == "not_found":
        findings.append(finding("LOW", "No MX records found", "The target domain has no visible MX records.", "If the domain sends or receives email, configure MX and email authentication records.", "medium", fid="DNX-MAIL-001", category="Mail Security"))

    spf = mail.get("spf", {})
    if _status_is_not_found(spf):
        findings.append(finding("MEDIUM", "Missing SPF record", "No TXT record beginning with v=spf1 was found at the root domain.", "Publish an SPF policy that authorizes legitimate outbound mail servers.", "high", fid="DNX-MAIL-002", category="Mail Security"))
    elif _status_is_unknown(spf):
        findings.append(finding("INFO", "SPF status unknown", spf.get("lookup_error") or "TXT lookup was inconclusive.", "Retry with a larger --timeout/--lifetime before reporting SPF as missing.", "low", fid="DNX-MAIL-002U", category="Mail Security"))
    else:
        joined = " ".join(spf.get("records", [])).lower()
        all_mech = str(spf.get("all_mechanism") or "").lower()
        if "+all" in joined or all_mech in {"+all", "?all"}:
            findings.append(finding("HIGH", "Weak SPF all mechanism", "; ".join(spf.get("records", [])), "Avoid permissive SPF policies. Prefer a controlled softfail or hardfail policy after validation.", "high", fid="DNX-MAIL-003", category="Mail Security"))
        elif "~all" in joined:
            findings.append(finding("INFO", "SPF uses softfail", "; ".join(spf.get("records", [])), "Softfail may be fine during rollout; consider hardfail when confident.", "high", fid="DNX-MAIL-004", category="Mail Security"))
        if len(spf.get("records", [])) > 1:
            findings.append(finding("MEDIUM", "Multiple SPF records found", "; ".join(spf.get("records", [])), "Publish exactly one SPF TXT record; multiple SPF records can cause permanent SPF errors.", "high", fid="DNX-MAIL-005", category="Mail Security"))
        if spf.get("dns_lookup_estimate", 0) > 10:
            findings.append(finding("HIGH", "SPF exceeds DNS lookup limit", str(spf.get("dns_lookup_estimate")), "Reduce SPF includes, redirects, mx, a, ptr and exists mechanisms to stay within the 10-lookup SPF limit.", "medium", fid="DNX-MAIL-006", category="Mail Security"))
        elif spf.get("dns_lookup_estimate", 0) >= 8:
            findings.append(finding("LOW", "SPF close to DNS lookup limit", str(spf.get("dns_lookup_estimate")), "Review SPF includes to avoid future permanent errors as vendors change.", "medium", fid="DNX-MAIL-007", category="Mail Security"))

    dmarc = mail.get("dmarc", {})
    if _status_is_not_found(dmarc):
        findings.append(finding("MEDIUM", "Missing DMARC record", f"No DMARC TXT record found at {dmarc.get('name', '_dmarc.<domain>')}.", "Publish a DMARC record and move toward quarantine/reject after monitoring.", "high", fid="DNX-MAIL-008", category="Mail Security"))
    elif _status_is_unknown(dmarc):
        findings.append(finding("INFO", "DMARC status unknown", dmarc.get("lookup_error") or "DMARC lookup was inconclusive.", "Retry with a larger --timeout/--lifetime before reporting DMARC as missing.", "low", fid="DNX-MAIL-008U", category="Mail Security"))
    else:
        policy = str(dmarc.get("policy") or "").lower()
        pct = str(dmarc.get("pct") or "100")
        if policy == "none":
            findings.append(finding("LOW", "DMARC policy is monitoring only", "; ".join(dmarc.get("records", [])), "After validating reports, consider p=quarantine or p=reject.", "high", fid="DNX-MAIL-009", category="Mail Security"))
        elif not policy:
            findings.append(finding("LOW", "DMARC policy missing p= tag", "; ".join(dmarc.get("records", [])), "Add an explicit p= policy tag.", "high", fid="DNX-MAIL-010", category="Mail Security"))
        if pct.isdigit() and int(pct) < 100 and policy in {"quarantine", "reject"}:
            findings.append(finding("INFO", "DMARC enforcement is partially rolled out", f"pct={pct}", "Confirm the partial rollout is intentional and plan movement toward pct=100.", "medium", fid="DNX-MAIL-011", category="Mail Security"))
        if not dmarc.get("rua"):
            findings.append(finding("INFO", "DMARC aggregate reporting address missing", "No rua= tag was found.", "Add rua= reporting so domain owners can monitor authentication results.", "medium", fid="DNX-MAIL-012", category="Mail Security"))

    mta_sts = mail.get("mta_sts", {})
    tls_rpt = mail.get("tls_rpt", {})
    if mail.get("mx") and mta_sts.get("checked") and _status_is_not_found(mta_sts):
        findings.append(finding("INFO", "MTA-STS DNS policy not detected", f"No v=STSv1 TXT found at {mta_sts.get('name', '_mta-sts.' + domain)}.", "Consider MTA-STS and TLS-RPT for stronger inbound mail transport security.", "medium", fid="DNX-MAIL-013", category="Mail Security"))
    if mail.get("mx") and tls_rpt.get("checked") and _status_is_not_found(tls_rpt):
        findings.append(finding("INFO", "TLS-RPT record not detected", f"No v=TLSRPTv1 TXT found at {tls_rpt.get('name', '_smtp._tls.' + domain)}.", "Consider TLS-RPT to receive reports about mail TLS delivery problems.", "medium", fid="DNX-MAIL-014", category="Mail Security"))

    if _status_is_not_found(caa):
        findings.append(finding("LOW", "Missing CAA record", "No CAA records were found for the domain.", "Consider publishing CAA records to restrict certificate issuance to approved CAs.", "high", fid="DNX-PKI-001", category="PKI"))
    elif _status_is_unknown(caa):
        findings.append(finding("INFO", "CAA status unknown", caa.get("error") or "CAA lookup was inconclusive.", "Retry with a larger --timeout/--lifetime before reporting CAA as missing.", "low", fid="DNX-PKI-001U", category="PKI"))
    elif caa.get("issue") and not caa.get("issuewild"):
        findings.append(finding("INFO", "CAA wildcard issuance not explicitly controlled", "CAA issue records exist, but no issuewild tag was found.", "If wildcard certificates are used or prohibited, define issuewild explicitly.", "medium", fid="DNX-PKI-002", category="PKI"))

    if dnssec.get("status") == "unknown":
        findings.append(finding("INFO", "DNSSEC status unknown", dnssec.get("state", "unknown"), "Retry with a larger --timeout/--lifetime before reporting DNSSEC as missing or misconfigured.", "low", fid="DNX-DNSSEC-000U", category="DNSSEC"))
    elif not dnssec.get("appears_enabled"):
        findings.append(finding("INFO", "DNSSEC not detected", "No DS, DNSKEY, or RRSIG records were detected by the scanner.", "Consider DNSSEC if it fits the domain's operational requirements.", "medium", fid="DNX-DNSSEC-001", category="DNSSEC"))
    elif dnssec.get("state") != "signed_with_parent_ds":
        findings.append(finding("MEDIUM", "DNSSEC appears partial or misconfigured", dnssec.get("state", "unknown"), "Validate the DNSSEC chain of trust and parent/child delegation state.", "medium", fid="DNX-DNSSEC-002", category="DNSSEC"))
    if dnssec.get("weak_algorithms"):
        findings.append(finding("LOW", "DNSSEC weak algorithm detected", "; ".join(a.get("record", "") for a in dnssec.get("weak_algorithms", [])[:5]), "Consider modern DNSSEC algorithms such as ECDSAP256SHA256 or Ed25519 where supported.", "medium", fid="DNX-DNSSEC-003", category="DNSSEC"))

    if any(item.get("vulnerable") for item in zone):
        findings.append(finding("HIGH", "Zone transfer appears possible", "At least one authoritative nameserver returned AXFR data.", "Disable public AXFR and restrict zone transfers to authorized secondary DNS servers.", "high", fid="DNX-DNS-004", category="DNS"))

    if wildcard.get("detected"):
        findings.append(finding("LOW", "Wildcard DNS detected", ", ".join(wildcard.get("wildcard_values", [])) or "Random subdomains resolved.", "Treat brute-force subdomain results carefully; filter wildcard false positives.", "high", fid="DNX-DNS-005", category="DNS"))

    takeover_candidates = []
    for cname in records.get("CNAME", {}).get("values", []) or []:
        if fingerprint_provider(cname):
            takeover_candidates.append(cname)
    for item in subdomains.get("verified_subdomains", []) + subdomains.get("active", []):
        for cname in item.get("cname", []):
            if fingerprint_provider(cname):
                takeover_candidates.append(f"{item.get('name')} -> {cname}")
    for candidate in takeover.get("candidates", []) or []:
        takeover_candidates.append(f"{candidate.get('asset')} -> {candidate.get('cname')} ({candidate.get('provider')})")
    if takeover_candidates:
        findings.append(finding("MEDIUM", "CNAME points to takeover-prone provider", "; ".join(sorted(set(takeover_candidates))[:20]), "Manually verify whether the referenced cloud resource is claimed and active.", "medium", fid="DNX-TAKEOVER-001", category="Takeover", affected_assets=sorted(set(takeover_candidates))[:20]))

    if resolver_comparison.get("difference_count", 0) > 0:
        diff_types = ", ".join(d.get("record_type", "?") for d in resolver_comparison.get("differences", []))
        findings.append(finding("INFO", "Resolver comparison found differing answers", f"Different public resolvers returned different answers for: {diff_types}.", "Review CDN, GeoDNS, DNS propagation, and resolver caching before treating one answer as authoritative.", "high", fid="DNX-DNS-006", category="DNS"))

    passive = subdomains.get("passive", {})
    passive_enabled = bool(result.get("scan_profile", {}).get("passive_checks"))
    if passive_enabled and passive.get("error") and subdomains.get("count", 0) == 0:
        findings.append(finding("INFO", "Passive source returned no usable data", passive.get("error", "Passive source unavailable."), "Retry later, increase --timeout, or combine dnsRecon with another passive source export.", "medium", fid="DNX-PASSIVE-001", category="Subdomain Discovery"))

    expiring = [item for item in tls if item.get("ok") and item.get("expires_in_days") is not None and item.get("expires_in_days") < 30]
    if expiring:
        findings.append(finding("MEDIUM", "TLS certificate expiring soon", "; ".join(f"{x.get('host')}: {x.get('expires_in_days')} days" for x in expiring[:10]), "Renew or rotate certificates before expiration.", "high", fid="DNX-TLS-001", category="TLS", affected_assets=[x.get("host") for x in expiring[:10]]))

    admin_hosts = [item.get("host") for item in http if item.get("alive") and any(token in item.get("host", "") for token in ["admin", "grafana", "kibana", "jenkins", "jira", "vpn", "sso"])]
    if admin_hosts:
        findings.append(finding("INFO", "Administrative-looking web hosts detected", ", ".join(admin_hosts[:20]), "Prioritize these hosts for authorized web review and access-control validation.", "medium", fid="DNX-WEB-001", category="Web Surface", affected_assets=admin_hosts[:20]))

    return sort_findings(findings)
