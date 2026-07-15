"""Config loading and strict unknown-key rejection (NFR-5)."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from eventiq.config import Config, ConfigError, load_config

REPO = Path(__file__).resolve().parents[2]


def test_defaults() -> None:
    cfg = Config()
    assert cfg.engine == "stdlib"
    assert cfg.brute_force.ports == [22, 3389]
    assert cfg.port_scan.refused_statuses == ["BLOCKED"]


def test_load_shipped_default_yaml() -> None:
    cfg = load_config(REPO / "config" / "default.yml")
    assert "powershell-download.site" in cfg.suspicious_domain.iocs
    assert len(cfg.not_detected) == 2


def test_baked_in_detection_defaults_match_shipped_yaml() -> None:
    """The obvious no-``-c`` path must not silently run weaker detection."""
    baked = asdict(load_config(None))
    shipped = asdict(load_config(REPO / "config" / "default.yml"))

    # These notes describe known traps in the supplied 1M-row dataset. They are
    # report narrative, not detection configuration, so generic uploads must
    # not inherit them from the baked-in defaults.
    assert baked.pop("not_detected") == []
    assert len(shipped.pop("not_detected")) == 2

    assert baked == shipped


def test_unknown_top_level_key_rejected(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("engine: stdlib\nnonsense: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown top-level"):
        load_config(p)


def test_unknown_nested_key_rejected(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("port_scan:\n  min_distinct_sources: 10\n  typo: 5\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown config key"):
        load_config(p)


def test_bad_engine_rejected(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("engine: sqlite\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="engine must be"):
        load_config(p)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yml")
