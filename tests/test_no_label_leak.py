"""Guard: the detection engine must never read the held-out label columns.

This is the project's headline guarantee made mechanical (PLAN section 2). If any
detector or the engine ever references event_type or severity, this test goes red.
"""

from __future__ import annotations

from pathlib import Path

import eventiq

FORBIDDEN = ("event_type", "severity")


def _detection_sources() -> list[Path]:
    root = Path(eventiq.__file__).parent
    files = list((root / "detectors").glob("*.py"))
    files += [root / "engine.py", root / "windows.py"]
    return files


def test_detectors_never_reference_label_columns() -> None:
    offenders = []
    for path in _detection_sources():
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.name} contains {needle!r}")
    assert not offenders, offenders


def test_event_has_no_label_fields() -> None:
    from eventiq.model import Event

    names = set(Event.__dataclass_fields__)
    assert "event_type" not in names
    assert "severity" not in names
