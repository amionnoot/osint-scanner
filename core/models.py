"""Datenmodelle für den OSINT-Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    """Bewertungsstufen für Sicherheitshinweise."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModuleStatus(Enum):
    """Status eines Modullaufs."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Finding:
    """Ein einzelnes Ergebnis / Fund aus der OSINT-Analyse."""
    title: str
    description: str
    severity: Severity
    source_module: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source_module": self.source_module,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp,
        }


@dataclass
class ModuleResult:
    """Ergebnis eines einzelnen Moduls."""
    module_name: str
    status: ModuleStatus
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "status": self.status.value,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    """Gesamtergebnis eines Scans."""
    target_domain: str
    target_organization: str
    scan_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_end: str = ""
    module_results: list[ModuleResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for mr in self.module_results:
            findings.extend(mr.findings)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "target_organization": self.target_organization,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "summary": {
                "total_modules": len(self.module_results),
                "total_findings": len(self.all_findings),
                "findings_by_severity": self.count_by_severity(),
            },
            "module_results": [mr.to_dict() for mr in self.module_results],
        }

    def count_by_severity(self) -> dict[str, int]:
        """Zählt Findings gruppiert nach Severity-Stufe."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts