from dnx.core.resolver import QueryResult
from dnx.findings.rules import analyze_findings
from dnx.modules.dns_health import analyze_dns_health
from dnx.modules.nameservers import analyze_nameservers


class _Config:
    concurrency = 10


class _FakeResolver:
    config = _Config()

    def resolve(self, name, record_type):
        if record_type == "NS":
            return QueryResult(record_type="NS", name=name, values=["ns1.example.net."])
        raise AssertionError("unexpected direct resolve")

    def resolve_many(self, hosts, record_types, concurrency=None):
        return {
            "ns1.example.net": {
                "A": QueryResult(record_type="A", name="ns1.example.net", values=[], error="Timeout", error_type="TIMEOUT"),
                "AAAA": QueryResult(record_type="AAAA", name="ns1.example.net", values=[], error="Timeout", error_type="TIMEOUT"),
            }
        }


def test_nameserver_timeout_is_unknown_not_unresolved():
    ns = analyze_nameservers("example.com", _FakeResolver())
    assert ns["servers"][0]["status"] == "unknown"

    health = analyze_dns_health("example.com", _FakeResolver(), ns, {"NS": {"values": ["ns1.example.net."]}, "SOA": {"values": ["ns1.example.net. hostmaster.example.com. 1 1 1 1 1"]}})
    titles = {issue["title"] for issue in health["issues"]}
    assert "Nameserver host does not resolve" not in titles

    result = {
        "records": {"A": {"values": ["192.0.2.1"]}, "AAAA": {"values": []}, "NS": {"values": ["ns1.example.net."]}, "CNAME": {"values": []}},
        "mail_security": {},
        "dnssec": {"status": "unknown", "appears_enabled": False, "state": "timeout"},
        "caa": {"status": "unknown", "found": False},
        "zone_transfer": [],
        "wildcard": {"detected": False},
        "nameservers": ns,
        "subdomains": {"active": [], "verified_subdomains": [], "passive": {}},
        "resolver_comparison": {"difference_count": 0, "differences": []},
        "scan_profile": {"profile": "quick", "passive_checks": False},
        "dns_health": health,
    }
    findings = analyze_findings(result)
    titles = {f["title"] for f in findings}
    assert "Some nameservers did not resolve" not in titles
    assert "Nameserver resolution unknown" in titles
