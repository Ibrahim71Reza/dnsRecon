from dnx.modules.takeover import fingerprint_provider


def test_takeover_provider_fingerprint():
    assert fingerprint_provider("example.github.io") == "GitHub Pages"
    assert fingerprint_provider("safe.example.com") is None
