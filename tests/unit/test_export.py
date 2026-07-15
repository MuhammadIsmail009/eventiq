"""Exports produce well-formed, deterministic Wazuh XML and Sigma YAML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import yaml

from eventiq.config import Config
from eventiq.export import build_sigma, build_wazuh_xml


def test_wazuh_xml_is_well_formed_and_covers_rules() -> None:
    xml = build_wazuh_xml(Config())
    root = ET.fromstring(xml)  # raises if malformed
    assert root.tag == "group"
    ids = {r.get("id") for r in root.findall("rule")}
    # detector rules plus the two frequency base rules
    for rid in (
        "100100", "100200", "100300", "100400", "100500", "100600",
        "100700", "100710",
        # classic single-source rules (Phase 7)
        "100110", "100120", "100121", "100210", "100130",
    ):
        assert rid in ids
    # brute/scan use frequency + different source IPs
    brute = root.find("./rule[@id='100100']")
    assert brute is not None and brute.get("frequency") == "50"
    assert brute.find("different_srcip") is not None
    # classic port scan: one source, many ports
    cps = root.find("./rule[@id='100210']")
    assert cps is not None and cps.find("same_srcip") is not None
    assert cps.find("different_dstport") is not None
    # lateral movement: one source, many hosts
    lm = root.find("./rule[@id='100130']")
    assert lm is not None and lm.find("different_dstip") is not None


def test_sigma_yaml_loads_and_has_correlation() -> None:
    text = build_sigma(Config())
    docs = list(yaml.safe_load_all(text))
    titles = [d["title"] for d in docs if d]
    assert any("brute force" in t.lower() for t in titles)
    correlations = [d for d in docs if d and "correlation" in d]
    # distributed brute + scan, plus 5 classic correlations (port scan, brute,
    # spray A, spray B, lateral movement)
    assert len(correlations) == 7
    corr_types = {c["correlation"]["type"] for c in correlations}
    assert corr_types == {"value_count", "event_count"}
    lateral = next(d for d in docs if d and d.get("title", "").startswith("Lateral movement"))
    assert lateral["correlation"]["condition"] == {"gte": 5, "field": "dstip"}
    brute_corr = next(
        d for d in correlations if d["correlation"]["rules"] == ["eventiq_failed_auth"]
    )
    assert brute_corr["correlation"]["type"] == "value_count"
    assert brute_corr["correlation"]["condition"] == {"gte": 50, "field": "srcip"}
    assert "attack.t1110.003" in brute_corr["tags"]
    bits = next(d for d in docs if d and "Bitsadmin" in d["title"])
    cert = next(d for d in docs if d and "Certutil" in d["title"])
    assert bits["related"][0]["id"] == "d059842b-6b9d-4ed1-b5c3-5b89143c6ede"
    assert cert["related"][0]["id"] == "19b08b1c-861d-4e75-a1ef-ea0c1baf202b"


def test_exports_are_deterministic() -> None:
    assert build_wazuh_xml(Config()) == build_wazuh_xml(Config())
    assert build_sigma(Config()) == build_sigma(Config())


def test_sigma_uuids_are_stable() -> None:
    # uuid5-based ids must not change between runs
    a = {d["id"] for d in yaml.safe_load_all(build_sigma(Config())) if d and "id" in d}
    b = {d["id"] for d in yaml.safe_load_all(build_sigma(Config())) if d and "id" in d}
    assert a == b and len(a) >= 6
