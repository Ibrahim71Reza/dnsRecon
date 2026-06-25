from dnx.output.markdown_report import build_markdown


def sample_result():
    return {
        "target": {"domain": "example.com"},
        "version": "2.0.0",
        "mode": "safe",
        "generated_at": "2026-01-01T00:00:00Z",
        "duration_seconds": 0.1,
        "risk": {"score": 100, "level": "LOW"},
        "scan_profile": {"resolver": None, "effective_resolvers": ["1.1.1.1"], "active_checks": False, "passive_checks": True, "verify_subdomains": False},
        "records": {"A": {"values": ["93.184.216.34"], "ttl": 300}},
        "nameservers": {"servers": []},
        "mail_security": {"mx": [], "spf": {"records": [], "includes": []}, "dmarc": {"records": [], "policy": None}, "dkim": {"found": []}},
        "dnssec": {"appears_enabled": False, "ds_records": []},
        "caa": {"records": []},
        "reverse_dns": [],
        "zone_transfer": [],
        "subdomains": {"count": 0, "unique_subdomains": [], "verified_count": 0, "passive": {"sources": []}},
        "resolver_comparison": {"enabled": False},
        "findings": [],
        "whois": {"error": "offline"},
    }


def test_markdown_contains_domain_and_risk():
    md = build_markdown(sample_result())
    assert "example.com" in md
    assert "DNS Records" in md
    assert "Risk score" in md
