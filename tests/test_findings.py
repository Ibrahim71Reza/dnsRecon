from dnx.findings.rules import analyze_findings
from dnx.findings.score import risk_score


def test_missing_mail_security_findings():
    result = {
        "records": {"A": {"values": ["1.2.3.4"]}, "AAAA": {"values": []}, "CNAME": {"values": []}},
        "mail_security": {"mx": [], "spf": {"found": False}, "dmarc": {"found": False, "name": "_dmarc.example.com"}},
        "dnssec": {"appears_enabled": False},
        "caa": {"found": False},
        "zone_transfer": [],
        "wildcard": {"detected": False},
        "nameservers": {"count": 1, "servers": [{"host": "ns1.example.com", "status": "ok"}]},
        "subdomains": {"active": [], "verified_subdomains": [], "passive": {}},
        "resolver_comparison": {"difference_count": 0, "differences": []},
    }
    findings = analyze_findings(result)
    titles = {f["title"] for f in findings}
    assert "Missing SPF record" in titles
    assert "Missing DMARC record" in titles
    assert "Missing CAA record" in titles
    assert all("confidence" in f for f in findings)


def test_risk_score_penalizes_high_findings():
    score = risk_score([{"severity": "HIGH"}, {"severity": "LOW"}])
    assert score["score"] == 70
    assert score["counts"]["HIGH"] == 1
