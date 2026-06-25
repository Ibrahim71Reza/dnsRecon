from dnx.core.target import normalize_target


def test_normalize_plain_domain():
    target = normalize_target("Example.COM")
    assert target.domain == "example.com"


def test_normalize_url():
    target = normalize_target("https://www.example.com/path?q=1")
    assert target.domain == "www.example.com"


def test_invalid_domain():
    try:
        normalize_target("not a domain")
    except ValueError:
        assert True
    else:
        assert False
