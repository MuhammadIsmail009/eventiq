"""Generate Sigma rules from the EventIQ config.

Brute force and port scan are Sigma *correlation* rules (value_count of distinct
sources per destination), because there is no stock Sigma rule for a distributed
campaign and Wazuh rule 0095 is the reference for the shape. The content
detections are ordinary Sigma detections. UUIDs are deterministic (uuid5 of the
rule name) so the output is byte-stable across runs (NFR-3).
"""

from __future__ import annotations

import uuid

import yaml

from ..config import Config
from ..model import level_to_severity

# Fixed namespace so uuid5 rule ids are stable and byte-reproducible.
_NS = uuid.UUID("8f2a1c2e-0b0b-5a00-a000-105e12750000")


def _uid(name: str) -> str:
    return str(uuid.uuid5(_NS, f"eventiq/{name}"))


def _tags(mitre: list[str]) -> list[str]:
    return [f"attack.{m.lower()}" for m in mitre]


def _level(wazuh_level: int) -> str:
    return level_to_severity(wazuh_level).lower()


def _dump(doc: dict[str, object]) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False).strip()


def build_sigma(config: Config) -> str:
    docs: list[str] = []
    bf = config.brute_force
    ps = config.port_scan

    # --- Brute force: base detection + value_count correlation ---
    docs.append(_dump({
        "title": "Failed authentication on a monitored service (EventIQ base)",
        "id": _uid("brute-base"),
        "name": "eventiq_failed_auth",
        "status": "experimental",
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"status": "FAILED", "dstport": list(bf.ports)},
            "condition": "selection",
        },
    }))
    docs.append(_dump({
        "title": "Distributed brute force / password spray",
        "id": _uid("brute-correlation"),
        "status": "experimental",
        "description": (
            f"{bf.min_distinct_sources}+ distinct source IPs failing auth against one "
            "host within the window (distributed campaign)."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_failed_auth"],
            "group-by": ["dstip"],
            "timespan": "10m",
            "condition": {"gte": bf.min_distinct_sources, "field": "srcip"},
        },
        "level": _level(bf.level),
        "tags": _tags(bf.mitre),
    }))

    # --- Port scan: base refused connection + value_count correlation ---
    docs.append(_dump({
        "title": "Refused connection attempt (EventIQ base)",
        "id": _uid("scan-base"),
        "name": "eventiq_refused_conn",
        "status": "experimental",
        "logsource": {"category": "firewall"},
        "detection": {
            "selection": {"status": list(ps.refused_statuses)},
            "condition": "selection",
        },
    }))
    docs.append(_dump({
        "title": "Distributed port scan",
        "id": _uid("scan-correlation"),
        "status": "experimental",
        "description": (
            f"{ps.min_distinct_sources}+ distinct source IPs refused by one host "
            "within the window (distributed scan)."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_refused_conn"],
            "group-by": ["dstip"],
            "timespan": "10m",
            "condition": {"gte": ps.min_distinct_sources, "field": "srcip"},
        },
        "level": _level(ps.level),
        "tags": _tags(ps.mitre),
    }))

    # --- Classic single-source detections (Phase 7) ---
    # Base detections plus Sigma correlation rules. The native detectors use a
    # sliding time window per source; Sigma expresses this as value_count /
    # event_count correlations with a timespan.
    cbf = config.classic_brute_force
    cps = config.classic_port_scan
    spray = config.password_spray
    lm = config.lateral_movement

    docs.append(_dump({
        "title": "Failed authentication, any service (EventIQ base)",
        "id": _uid("classic-failed-auth"),
        "name": "eventiq_failed_auth_any",
        "status": "experimental",
        "logsource": {"category": "authentication"},
        "detection": {"selection": {"status": "FAILED"}, "condition": "selection"},
    }))
    docs.append(_dump({
        "title": "Connection carrying a destination port (EventIQ base)",
        "id": _uid("classic-connection"),
        "name": "eventiq_connection",
        "status": "experimental",
        "logsource": {"category": "network_connection"},
        "detection": {"selection": {"protocol": ["TCP", "UDP"]}, "condition": "selection"},
    }))
    docs.append(_dump({
        "title": "Failed auth on a remote-service port (EventIQ base)",
        "id": _uid("classic-failed-auth-remote"),
        "name": "eventiq_failed_auth_remote",
        "status": "experimental",
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"status": "FAILED", "dstport": list(lm.ports)},
            "condition": "selection",
        },
    }))

    win_m = max(1, cps.window_seconds // 60)
    docs.append(_dump({
        "title": "Classic port scan (single source, many ports)",
        "id": _uid("classic-port-scan"),
        "status": "experimental",
        "description": (
            f"One source touching {cps.min_ports}+ distinct ports of one host "
            f"within {win_m}m."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_connection"],
            "group-by": ["srcip", "dstip"],
            "timespan": f"{win_m}m",
            "condition": {"gte": cps.min_ports, "field": "dstport"},
        },
        "level": _level(cps.level),
        "tags": _tags(cps.mitre),
    }))
    bf_m = max(1, cbf.window_seconds // 60)
    docs.append(_dump({
        "title": "Classic brute force (single source, repeated failures)",
        "id": _uid("classic-brute-force"),
        "status": "experimental",
        "description": (
            f"{cbf.min_failures}+ failed auth from one source to one host within {bf_m}m."
        ),
        "correlation": {
            "type": "event_count",
            "rules": ["eventiq_failed_auth_any"],
            "group-by": ["srcip", "dstip"],
            "timespan": f"{bf_m}m",
            "condition": {"gte": cbf.min_failures},
        },
        "level": _level(cbf.level),
        "tags": _tags(cbf.mitre),
    }))
    sp_m = max(1, spray.window_seconds // 60)
    docs.append(_dump({
        "title": "Password spray (one source, many usernames)",
        "id": _uid("password-spray-a"),
        "status": "experimental",
        "description": (
            f"One source failing {spray.min_usernames}+ distinct usernames on one "
            f"host within {sp_m}m."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_failed_auth_any"],
            "group-by": ["srcip", "dstip"],
            "timespan": f"{sp_m}m",
            "condition": {"gte": spray.min_usernames, "field": "srcuser"},
        },
        "level": _level(spray.level),
        "tags": _tags(spray.mitre),
    }))
    docs.append(_dump({
        "title": "Password spray (many sources, one account)",
        "id": _uid("password-spray-b"),
        "status": "experimental",
        "description": (
            f"{spray.min_sources}+ distinct sources failing one account on one host. "
            f"The native rule also caps this below {spray.max_sources} sources to "
            "defer the large distributed campaign to the distributed brute-force "
            "rule; Sigma cannot express that upper bound."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_failed_auth_any"],
            "group-by": ["dstip", "srcuser"],
            "timespan": "24h",
            "condition": {"gte": spray.min_sources, "field": "srcip"},
        },
        "level": _level(spray.level),
        "tags": _tags(spray.mitre),
    }))
    lm_m = max(1, lm.window_seconds // 60)
    docs.append(_dump({
        "title": "Lateral movement fan-out (one source, many hosts)",
        "id": _uid("lateral-movement"),
        "status": "experimental",
        "description": (
            f"One source failing auth across {lm.min_hosts}+ hosts on remote-service "
            f"ports within {lm_m}m."
        ),
        "correlation": {
            "type": "value_count",
            "rules": ["eventiq_failed_auth_remote"],
            "group-by": ["srcip"],
            "timespan": f"{lm_m}m",
            "condition": {"gte": lm.min_hosts, "field": "dstip"},
        },
        "level": _level(lm.level),
        "tags": _tags(lm.mitre),
    }))

    # --- DNS tunneling (coarse; entropy is not expressible in Sigma) ---
    dt = config.dns_tunnel
    docs.append(_dump({
        "title": "Possible DNS tunneling (long random subdomain)",
        "id": _uid("dns-tunnel"),
        "status": "experimental",
        "description": (
            "Coarse net: long random subdomain label. EventIQ itself uses Shannon "
            "entropy plus unique-subdomain volume, which Sigma cannot compute."
        ),
        "logsource": {"category": "dns"},
        "detection": {
            "selection": {"domain|re": f"[a-z0-9]{{{dt.min_label_len},}}\\."},
            "condition": "selection",
        },
        "level": _level(dt.level),
        "tags": _tags(dt.mitre),
    }))

    # --- Suspicious domains (IOC list) ---
    sd = config.suspicious_domain
    docs.append(_dump({
        "title": "Connection to known-suspicious domain",
        "id": _uid("suspicious-domain"),
        "status": "experimental",
        "logsource": {"category": "dns"},
        "detection": {
            "selection": {"domain": list(sd.iocs)},
            "condition": "selection",
        },
        "level": _level(sd.level),
        "tags": _tags(sd.mitre),
    }))

    # --- Malicious PowerShell ---
    pw = config.powershell
    docs.append(_dump({
        "title": "Malicious PowerShell command pattern",
        "id": _uid("powershell"),
        "status": "experimental",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "command|contains": [
                    "-enc",
                    "DownloadString",
                    "-WindowStyle Hidden",
                    "-ExecutionPolicy Bypass",
                ]
            },
            "condition": "selection",
        },
        "level": _level(pw.level),
        "tags": _tags(pw.mitre),
    }))

    # --- Curated SigmaHQ-derived Windows download behaviours ---
    sc = config.sigma_commands
    enabled = set(sc.enabled_rules)
    if "bitsadmin_download" in enabled:
        docs.append(_dump({
            "title": "File Download Via Bitsadmin (EventIQ mapping)",
            "id": _uid("sigma-bitsadmin-download"),
            "related": [{
                "id": "d059842b-6b9d-4ed1-b5c3-5b89143c6ede",
                "type": "derived",
            }],
            "status": "test",
            "description": (
                "EventIQ mapping of the SigmaHQ Bitsadmin download behaviour."
            ),
            "references": [
                "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/"
                "process_creation/proc_creation_win_bitsadmin_download.yml"
            ],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection_img": [
                    {"Image|endswith": "\\bitsadmin.exe"},
                    {"OriginalFileName": "bitsadmin.exe"},
                ],
                "selection_transfer": {"CommandLine|contains": " /transfer "},
                "selection_create": {"CommandLine|contains": [" /create ", " /addfile "]},
                "selection_http": {"CommandLine|contains": "http"},
                "condition": (
                    "selection_img and (selection_transfer or "
                    "(selection_create and selection_http))"
                ),
            },
            "falsepositives": ["Some legitimate administration tools use Bitsadmin."],
            "level": _level(sc.level),
            "tags": _tags(sc.mitre),
        }))
    if "certutil_download" in enabled:
        docs.append(_dump({
            "title": "Suspicious Download Via Certutil.EXE (EventIQ mapping)",
            "id": _uid("sigma-certutil-download"),
            "related": [{
                "id": "19b08b1c-861d-4e75-a1ef-ea0c1baf202b",
                "type": "derived",
            }],
            "status": "test",
            "description": (
                "EventIQ mapping of the SigmaHQ Certutil URL download behaviour."
            ),
            "references": [
                "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/"
                "process_creation/proc_creation_win_certutil_download.yml"
            ],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection_img": [
                    {"Image|endswith": "\\certutil.exe"},
                    {"OriginalFileName": "CertUtil.exe"},
                ],
                "selection_flags": {
                    "CommandLine|contains": ["urlcache ", "verifyctl ", "URL "]
                },
                "selection_http": {"CommandLine|contains": "http"},
                "condition": "all of selection_*",
            },
            "falsepositives": ["Unknown; validate against local administrative usage."],
            "level": _level(sc.level),
            "tags": _tags(sc.mitre),
        }))

    # --- C2 port ---
    c2 = config.c2_port
    docs.append(_dump({
        "title": "Traffic to known command-and-control port",
        "id": _uid("c2-port"),
        "status": "experimental",
        "logsource": {"category": "firewall"},
        "detection": {
            "selection": {"dstport": list(c2.ioc_ports)},
            "condition": "selection",
        },
        "level": _level(c2.level),
        "tags": _tags(c2.mitre),
    }))

    return "\n---\n".join(docs) + "\n"
