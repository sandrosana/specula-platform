from datetime import date

import pytest

from app.services.priority import PriorityFacts, evaluate, priority_level

THRESHOLD = 0.5


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (PriorityFacts(kev_date_added=date(2026, 9, 12), kev_ransomware_use="Known"), "P1"),
        (PriorityFacts(kev_date_added=date(2026, 9, 12), kev_ransomware_use="Unknown"), "P2"),
        (PriorityFacts(kev_date_added=date(2026, 9, 12)), "P2"),
        # KEV always wins over EPSS.
        (PriorityFacts(kev_date_added=date(2026, 9, 12), epss=0.99), "P2"),
        (PriorityFacts(epss=0.5), "P3"),
        (PriorityFacts(epss=0.49999, cvss_score=10.0), "P4"),
        # Ransomware use without a KEV entry cannot happen, and is not P1.
        (PriorityFacts(kev_ransomware_use="Known"), "P4"),
        (PriorityFacts(), "P4"),
    ],
)
def test_priority_level(facts: PriorityFacts, expected: str) -> None:
    assert priority_level(facts, THRESHOLD) == expected


def test_reason_carries_the_facts() -> None:
    level, reason = evaluate(
        PriorityFacts(
            kev_date_added=date(2026, 9, 12),
            kev_ransomware_use="Known",
            epss=0.94,
            epss_percentile=0.99,
            cvss_score=9.8,
            cvss_version="3.1",
            cvss_severity="CRITICAL",
        ),
        THRESHOLD,
    )

    assert level == "P1"
    assert reason == {
        "rule": "kev_ransomware",
        "kev": {"date_added": "2026-09-12", "ransomware_use": "Known"},
        "epss": {"score": 0.94, "percentile": 0.99},
        "epss_threshold": 0.5,
        "cvss": {"score": 9.8, "version": "3.1", "severity": "CRITICAL"},
    }


def test_reason_without_data() -> None:
    level, reason = evaluate(PriorityFacts(), 0.3)

    assert level == "P4"
    assert reason == {
        "rule": "severity",
        "kev": None,
        "epss": None,
        "epss_threshold": 0.3,
        "cvss": None,
    }
