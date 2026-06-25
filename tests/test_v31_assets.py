from __future__ import annotations

from dnx.output.assets import write_asset_exports


def test_asset_exports_written(tmp_path):
    result = {
        "target": {"domain": "example.com"},
        "records": {"A": {"values": ["93.184.216.34"]}, "AAAA": {"values": []}},
        "nameservers": {"servers": []},
        "subdomains": {
            "unique_subdomains": ["www.example.com", "api.example.com"],
            "verified_subdomains": [{"name": "www.example.com", "addresses": ["93.184.216.34"]}],
            "active": [{"name": "api.example.com", "resolved": True, "wildcard_match": False}],
        },
        "http": [{"host": "www.example.com", "urls": [{"url": "https://www.example.com", "alive": True, "status_code": 200}]}],
        "takeover": {"candidates": [{"asset": "old.example.com", "cname": "old.github.io", "provider": "GitHub Pages", "confidence": "medium", "source": "test"}]},
    }
    paths = write_asset_exports(result, tmp_path)
    assert len(paths) == 7
    assert "www.example.com" in (tmp_path / "example.com-subdomains.txt").read_text()
    assert "https://www.example.com" in (tmp_path / "example.com-live-urls.txt").read_text()
    assert "GitHub Pages" in (tmp_path / "example.com-takeover-candidates.csv").read_text()
