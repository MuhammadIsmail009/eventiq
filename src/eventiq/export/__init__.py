"""Export detected patterns as deployable Wazuh rule XML and Sigma YAML (FR-17).

These are generated from the config (thresholds, indicator lists, levels, MITRE
ids), so they mirror exactly what EventIQ detects. They are starting-point rules
a Wazuh or Sigma engineer would tune, not drop-in production rules: some EventIQ
logic (Shannon entropy, exact distinct-source counting) exceeds what a static rule
can express, and that is called out in the generated headers.
"""

from .sigma_yaml import build_sigma
from .wazuh_xml import build_wazuh_xml

__all__ = ["build_sigma", "build_wazuh_xml"]
