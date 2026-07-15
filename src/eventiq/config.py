"""Configuration loading with strict unknown-key rejection (NFR-5).

Every threshold, IOC list and rule level lives in YAML with safe defaults baked
into these dataclasses. No attack-specific constant (a target IP, a subnet)
appears here or in any detector: detectors key on structure, config carries
indicators only. Unknown keys are rejected rather than silently ignored.
"""

from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar

import yaml


class ConfigError(Exception):
    """Raised on an unreadable, malformed, or unknown-key configuration."""


@dataclass(slots=True)
class PortScanConfig:
    # Destination-pivot on REFUSED connection attempts (the scan signature; cf.
    # Snort sfPortscan "rejected" connections). Tracking only refused attempts
    # both matches the detection theory and keeps memory bounded to the tiny set
    # of hosts receiving refused traffic. Fires when many distinct sources probe
    # many ports of one host. Benign busiest host has 758 sources but 0 refused.
    min_distinct_sources: int = 50
    min_distinct_ports: int = 15
    refused_statuses: list[str] = field(default_factory=lambda: ["BLOCKED"])
    level: int = 12
    mitre: list[str] = field(default_factory=lambda: ["T1046"])


@dataclass(slots=True)
class BruteForceConfig:
    # Destination-pivot: a host receiving failed auth from an anomalous number of
    # distinct sources. Benign max observed: 28 distinct sources on one host;
    # the campaign has 15,926. Covers SSH (22) and RDP (3389). No username filter:
    # the detector keys on source convergence, usernames are evidence only.
    min_distinct_sources: int = 50
    services: list[str] = field(default_factory=lambda: ["ssh", "rdp"])
    ports: list[int] = field(default_factory=lambda: [22, 3389])
    level: int = 12
    mitre: list[str] = field(default_factory=lambda: ["T1110.003"])


@dataclass(slots=True)
class ClassicPortScanConfig:
    # Single-source port scan: one source touching many distinct ports of one
    # host inside a short window, any connection status. Complements the
    # distributed port_scan (100200), which needs 50+ refused sources and so is
    # blind to a lone scanner. Windowed benign ceiling on the 1M file: 2 ports.
    window_seconds: int = 300
    min_ports: int = 10
    level: int = 10
    mitre: list[str] = field(default_factory=lambda: ["T1046"])


@dataclass(slots=True)
class ClassicBruteForceConfig:
    # Single-source brute force: one source failing auth against one host many
    # times inside a short window. Complements the distributed brute_force
    # (100100). Windowed benign ceiling on the 1M file: 1 failure per window.
    window_seconds: int = 600
    min_failures: int = 8
    level: int = 10
    mitre: list[str] = field(default_factory=lambda: ["T1110.001"])


@dataclass(slots=True)
class PasswordSprayConfig:
    # Two spray shapes that the distributed rules miss:
    #  A) one source failing across many distinct usernames in a window
    #     (windowed benign ceiling on the 1M file: 1 username).
    #  B) many sources failing one account across the whole file, in the band
    #     below the distributed threshold (7..49 sources). Whole-file benign
    #     ceiling on the 1M file: 6 sources; the 15,926-source campaign sits
    #     above max_sources and is left to rule 100100.
    window_seconds: int = 600
    min_usernames: int = 5
    min_sources: int = 7
    max_sources: int = 50
    level: int = 10
    mitre: list[str] = field(default_factory=lambda: ["T1110.003"])


@dataclass(slots=True)
class LateralMovementConfig:
    # One source failing auth against many distinct hosts on remote-service
    # ports (SMB/RDP/WinRM) inside a window. Windowed benign ceiling on the 1M
    # file: 2 hosts.
    window_seconds: int = 600
    min_hosts: int = 5
    ports: list[int] = field(default_factory=lambda: [445, 3389, 5985, 5986])
    level: int = 12
    mitre: list[str] = field(default_factory=lambda: ["T1021"])


@dataclass(slots=True)
class DnsTunnelConfig:
    min_entropy: float = 3.0
    min_label_len: int = 20
    min_query_count: int = 5
    allowlist: list[str] = field(default_factory=list)
    level: int = 12
    mitre: list[str] = field(default_factory=lambda: ["T1071.004"])


@dataclass(slots=True)
class SuspiciousDomainConfig:
    iocs: list[str] = field(
        default_factory=lambda: [
            "powershell-download.site",
            "freevpn-access.click",
            "login-security-check.info",
            "remote-admin-panel.ru",
            "secure-update-check.xyz",
            "cdn-account-verify.top",
        ]
    )
    bad_tlds: list[str] = field(
        default_factory=lambda: ["click", "site", "top", "info", "xyz", "ru"]
    )
    level: int = 10
    mitre: list[str] = field(default_factory=lambda: ["T1071.004"])


@dataclass(slots=True)
class PowerShellConfig:
    patterns: list[str] = field(
        default_factory=lambda: [
            "encodedcommand",
            "downloadstring",
            "windowstyle_hidden",
            "executionpolicy_bypass",
        ]
    )
    level: int = 13
    mitre: list[str] = field(default_factory=lambda: ["T1059.001"])


@dataclass(slots=True)
class SigmaCommandConfig:
    """Conservative command-line behaviours derived from SigmaHQ rules."""

    enabled_rules: list[str] = field(
        default_factory=lambda: ["bitsadmin_download", "certutil_download"]
    )
    level: int = 10
    mitre: list[str] = field(default_factory=lambda: ["T1105"])


@dataclass(slots=True)
class C2PortConfig:
    ioc_ports: list[int] = field(default_factory=lambda: [4444])
    level: int = 12
    mitre: list[str] = field(default_factory=lambda: ["T1571"])


@dataclass(slots=True)
class NotDetected:
    name: str = ""
    reason: str = ""
    numbers: str = ""


@dataclass(slots=True)
class Config:
    engine: str = "stdlib"
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    classic_port_scan: ClassicPortScanConfig = field(default_factory=ClassicPortScanConfig)
    classic_brute_force: ClassicBruteForceConfig = field(
        default_factory=ClassicBruteForceConfig
    )
    password_spray: PasswordSprayConfig = field(default_factory=PasswordSprayConfig)
    lateral_movement: LateralMovementConfig = field(default_factory=LateralMovementConfig)
    dns_tunnel: DnsTunnelConfig = field(default_factory=DnsTunnelConfig)
    suspicious_domain: SuspiciousDomainConfig = field(default_factory=SuspiciousDomainConfig)
    powershell: PowerShellConfig = field(default_factory=PowerShellConfig)
    sigma_commands: SigmaCommandConfig = field(default_factory=SigmaCommandConfig)
    c2_port: C2PortConfig = field(default_factory=C2PortConfig)
    not_detected: list[NotDetected] = field(default_factory=list)


T = TypeVar("T")


def _build(cls: type[T], data: Any, path: str) -> T:
    """Construct a dataclass from a mapping, rejecting unknown keys."""
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping, got {type(data).__name__}")
    known = {f.name: f for f in fields(cls)}  # type: ignore[arg-type]
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError(f"{path}: unknown config key(s): {', '.join(sorted(unknown))}")
    kwargs: dict[str, Any] = {}
    for name, f in known.items():
        if name not in data:
            continue
        ftype = f.type
        if is_dataclass(ftype) and isinstance(ftype, type):
            kwargs[name] = _build(ftype, data[name], f"{path}.{name}")
        else:
            kwargs[name] = data[name]
    return cls(**kwargs)


def load_config(path: str | Path | None) -> Config:
    """Load and validate a config file. ``None`` yields baked-in defaults."""
    if path is None:
        return Config()
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {p}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file is not valid YAML: {exc}") from exc
    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    known = {f.name for f in fields(Config)}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"unknown top-level config key(s): {', '.join(sorted(unknown))}")

    kwargs: dict[str, Any] = {}
    for f in fields(Config):
        if f.name not in raw:
            continue
        if f.name == "engine":
            kwargs["engine"] = raw["engine"]
        elif f.name == "not_detected":
            items = raw["not_detected"] or []
            if not isinstance(items, list):
                raise ConfigError("not_detected: expected a list")
            kwargs["not_detected"] = [
                _build(NotDetected, item, f"not_detected[{i}]") for i, item in enumerate(items)
            ]
        else:
            ftype = f.type
            assert is_dataclass(ftype) and isinstance(ftype, type)
            kwargs[f.name] = _build(ftype, raw[f.name], f.name)
    cfg = Config(**kwargs)
    if cfg.engine not in ("stdlib", "polars"):
        raise ConfigError(f"engine must be 'stdlib' or 'polars', got {cfg.engine!r}")
    return cfg
