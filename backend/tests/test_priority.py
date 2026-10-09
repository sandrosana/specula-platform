from datetime import date

import pytest

from app.services.priority import (
    NO_DATE,
    PriorityFacts,
    PrioritySort,
    evaluate,
    priority_level,
    priority_sort,
)

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


def test_sort_key_follows_the_specification_order() -> None:
    cases = {
        "p1-old": PriorityFacts(kev_date_added=date(2026, 9, 1), kev_ransomware_use="Known"),
        "p1-new": PriorityFacts(
            kev_date_added=date(2026, 10, 1), kev_ransomware_use="Known", epss=0.1
        ),
        "p2": PriorityFacts(kev_date_added=date(2026, 10, 5), epss=0.99, cvss_score=10.0),
        "p3-high": PriorityFacts(epss=0.95),
        "p3-low-cvss": PriorityFacts(epss=0.6, cvss_score=5.0),
        "p3-low-critical": PriorityFacts(epss=0.6, cvss_score=9.8),
        "p4-critical": PriorityFacts(epss=0.01, cvss_score=9.8),
        "p4-critical-epss": PriorityFacts(epss=0.02, cvss_score=9.8),
        "p4-no-cvss": PriorityFacts(epss=0.4),
        "p4-nothing": PriorityFacts(),
    }

    def key(name: str) -> PrioritySort:
        facts = cases[name]
        return priority_sort(facts, priority_level(facts, THRESHOLD))

    ordered = sorted(
        cases,
        key=lambda name: (key(name).rank, key(name).kev_date, key(name).first, key(name).second),
        reverse=True,
    )
    assert ordered == [
        "p1-new",
        "p1-old",
        "p2",
        "p3-high",
        "p3-low-critical",
        "p3-low-cvss",
        "p4-critical-epss",
        "p4-critical",
        "p4-no-cvss",
        "p4-nothing",
    ]


def test_sort_key_ignores_kev_date_outside_p1_p2() -> None:
    assert priority_sort(PriorityFacts(epss=0.7), "P3") == PrioritySort(2, NO_DATE, 0.7, -1.0)


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
