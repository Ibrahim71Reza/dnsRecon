from dnx.modules.subdomains import load_words


def test_load_words_fallback():
    words = load_words(None)
    assert "www" in words
    assert "api" in words
