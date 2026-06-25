from dnx.findings.rules import analyze_findings


def test_unknown_mail_dnssec_caa_do_not_raise_missing_findings():
    result = {
        "records": {
            "A": {"values": [], "error_type": "TIMEOUT"},
            "AAAA": {"values": [], "error_type": "TIMEOUT"},
            "NS": {"values": [], "error_type": "TIMEOUT"},
            "SOA": {"values": [], "error_type": "TIMEOUT"},
            "CNAME": {"values": []},
        },
        "mail_security": {
            "mx": [],
            "mx_status": "unknown",
            "spf": {"found": False, "status": "unknown", "lookup_error": "Timeout"},
            "dmarc": {"found": False, "status": "unknown", "name": "_dmarc.example.com", "lookup_error": "Timeout"},
            "mta_sts": {"checked": False, "status": "skipped", "found": False},
            "tls_rpt": {"checked": False, "status": "skipped", "found": False},
        },
        "dnssec": {"status": "unknown", "appears_enabled": False, "state": "unknown_timeout"},
        "caa": {"status": "unknown", "found": False, "error": "Timeout"},
        "zone_transfer": [],
        "wildcard": {"detected": False},
        "nameservers": {"count": 0, "status": "unknown", "servers": []},
        "subdomains": {"active": [], "verified_subdomains": [], "passive": {}},
        "resolver_comparison": {"difference_count": 0, "differences": []},
        "scan_profile": {"profile": "quick", "passive_checks": False},
        "dns_health": {"issues": []},
    }
    titles = {f["title"] for f in analyze_findings(result)}
    assert "Missing SPF record" not in titles
    assert "Missing DMARC record" not in titles
    assert "Missing CAA record" not in titles
    assert "DNSSEC appears partial or misconfigured" not in titles
    assert "No nameserver records found" not in titles
    assert "No apex A/AAAA record found" not in titles
    assert "SPF status unknown" in titles
    assert "DNSSEC status unknown" in titles
