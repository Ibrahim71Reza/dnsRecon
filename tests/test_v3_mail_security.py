from dnx.modules.mail_security import parse_spf


def test_parse_spf_lookup_count_and_includes():
    parsed = parse_spf("v=spf1 include:_spf.google.com include:mailgun.org mx a -all")
    data = parsed.to_dict()
    assert data["includes"] == ["_spf.google.com", "mailgun.org"]
    assert data["all"] == "-all"
    assert data["dns_lookup_mechanisms"] == 4


def test_parse_spf_detects_permissive_all():
    parsed = parse_spf("v=spf1 +all")
    assert parsed.all == "+all"
    assert "SPF all mechanism is permissive" in parsed.issues
