"""Safe CSV compatibility without guessing unsupported schemas."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from eventiq.sources.csv_source import CsvSource, MalformedRowError


def test_partial_endpoint_schema_uses_aliases_and_stable_ids(tmp_path: Path) -> None:
    headers = [
        "command", "status", "target_user", "dest_ip", "source_ip",
        "timestamp", "event_type",
    ]
    rows = [
        {
            "timestamp": "2026-07-01 00:00:01",
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "target_user": "admin",
            "status": "failed",
            "command": "tool.exe --value=a,b",
            "event_type": "first-label",
        }
    ]

    ids: list[str] = []
    for n, label in enumerate(("first-label", "changed-label"), start=1):
        rows[0]["event_type"] = label
        path = tmp_path / f"partial-{n}.csv"
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=headers, lineterminator="\r\n")
            writer.writeheader()
            writer.writerows(rows)
        source = CsvSource(str(path))
        event = next(iter(source))
        ids.append(event.log_id)
        assert event.dstip == "10.0.0.2"
        assert event.srcuser == "admin"
        assert event.status == "FAILED"
        assert event.command == "tool.exe --value=a,b"
        assert event.srcport is None and event.dstport is None
        assert "log_id" in source.missing_optional
        assert "source_port" in source.missing_optional

    assert ids == ["row-000000001", "row-000000001"]


def test_missing_source_port_is_optional(dataset_csv: Path, tmp_path: Path) -> None:
    with open(dataset_csv, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))[:1]
    fields = [name for name in rows[0] if name != "source_port"]
    path = tmp_path / "no-source-port.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    source = CsvSource(str(path))
    event = next(iter(source))
    assert event.srcport is None
    assert source.missing_optional == ["source_port"]


def test_canonical_and_alias_conflict_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ambiguous.csv"
    path.write_text(
        "timestamp,source_ip,destination_ip,dest_ip\n"
        "2026-07-01 00:00:01,1.1.1.1,2.2.2.2,3.3.3.3\n",
        encoding="utf-8",
    )
    with pytest.raises(MalformedRowError, match="both 'destination_ip' and alias 'dest_ip'"):
        list(CsvSource(str(path)))

