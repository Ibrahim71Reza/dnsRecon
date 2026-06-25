from __future__ import annotations

from dnx.scanner import build_config


def test_build_config_export_assets_flag():
    cfg = build_config(export_assets=False, profile="quick")
    assert cfg.export_assets is False
    assert cfg.profile == "quick"
