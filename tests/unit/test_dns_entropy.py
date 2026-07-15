"""Entropy properties for DNS tunneling."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from eventiq.detectors.dns_tunnel import shannon_entropy


def test_empty_and_uniform() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0  # one symbol -> zero entropy


def test_random_label_beats_dictionary_word() -> None:
    high = shannon_entropy("7ig2sk1zhcdzsvymj1e9x19od2kwg84upg897c167v8669rmfhip7kv")
    low = shannon_entropy("github")
    assert high > 3.0
    assert high > low


@given(st.text(alphabet="abcdefghijklmnop0123456789", min_size=1, max_size=64))
def test_entropy_bounded_by_log2_alphabet(s: str) -> None:
    # Entropy never exceeds log2(number of distinct symbols present).
    import math

    distinct = len(set(s))
    assert 0.0 <= shannon_entropy(s) <= math.log2(distinct) + 1e-9
