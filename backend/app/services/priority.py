"""CVE priority levels P1-P4 (docs/specifica-funzionale-dashboard.md §6).

Each CVE belongs to the first level whose condition it meets:
P1 in KEV with ransomware use "Known", P2 in KEV, P3 EPSS >= threshold, P4 the rest.

The reason is stored as structured facts, not as a sentence: the UI builds the
text through its i18n files (e.g. "P3 - Non in KEV. EPSS 0.62 (98° percentile),
sopra la soglia 0.5. CVSS 8.8.").
"""

from dataclasses import dataclass
from datetime import date
from typing import Any, Literal

PriorityLevel = Literal["P1", "P2", "P3", "P4"]
PriorityRule = Literal["kev_ransomware", "kev", "epss_threshold", "severity"]

RULES: dict[PriorityLevel, PriorityRule] = {
    "P1": "kev_ransomware",
    "P2": "kev",
    "P3": "epss_threshold",
    "P4": "severity",
}
RANSOMWARE_KNOWN = "Known"


@dataclass(frozen=True)
class PriorityFacts:
    """What the level depends on, for one CVE."""

    kev_date_added: date | None = None
    kev_ransomware_use: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_severity: str | None = None

    @property
    def in_kev(self) -> bool:
        return self.kev_date_added is not None


def priority_level(facts: PriorityFacts, epss_threshold: float) -> PriorityLevel:
    if facts.in_kev and facts.kev_ransomware_use == RANSOMWARE_KNOWN:
        return "P1"
    if facts.in_kev:
        return "P2"
    if facts.epss is not None and facts.epss >= epss_threshold:
        return "P3"
    return "P4"


def priority_reason(
    facts: PriorityFacts, level: PriorityLevel, epss_threshold: float
) -> dict[str, Any]:
    """JSON-serializable facts behind `level`."""
    return {
        "rule": RULES[level],
        "kev": (
            {
                "date_added": facts.kev_date_added.isoformat(),
                "ransomware_use": facts.kev_ransomware_use,
            }
            if facts.kev_date_added is not None
            else None
        ),
        "epss": (
            {"score": facts.epss, "percentile": facts.epss_percentile}
            if facts.epss is not None
            else None
        ),
        "epss_threshold": epss_threshold,
        "cvss": (
            {
                "score": facts.cvss_score,
                "version": facts.cvss_version,
                "severity": facts.cvss_severity,
            }
            if facts.cvss_score is not None
            else None
        ),
    }


def evaluate(facts: PriorityFacts, epss_threshold: float) -> tuple[PriorityLevel, dict[str, Any]]:
    level = priority_level(facts, epss_threshold)
    return level, priority_reason(facts, level, epss_threshold)
