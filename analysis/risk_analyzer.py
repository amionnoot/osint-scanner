"""Aggregierte Risikoanalyse über alle Modulfunde."""

from __future__ import annotations

from typing import Any

from core.models import Severity, ScanResult


class RiskAnalyzer:
    """Bewertet die Gesamtlage auf Basis aller Findings."""

    SEVERITY_SCORES = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 3,
        Severity.HIGH: 5,
        Severity.CRITICAL: 10,
    }

    def __init__(self, scan_result: ScanResult) -> None:
        self.scan_result = scan_result

    def calculate_risk_score(self) -> float:
        findings = self.scan_result.all_findings
        if not findings:
            return 0.0
        total = sum(self.SEVERITY_SCORES[f.severity] for f in findings)
        max_possible = len(findings) * self.SEVERITY_SCORES[Severity.CRITICAL]
        return round((total / max_possible) * 100, 1) if max_possible else 0.0

    def risk_rating(self) -> str:
        score = self.calculate_risk_score()
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        return "INFORMATIONAL"

    def summary(self) -> dict[str, Any]:
        return {
            "risk_score": self.calculate_risk_score(),
            "risk_rating": self.risk_rating(),
            "total_findings": len(self.scan_result.all_findings),
            "findings_by_severity": self.scan_result.count_by_severity(),
            "top_findings": [
                f.to_dict()
                for f in sorted(
                    self.scan_result.all_findings,
                    key=lambda x: self.SEVERITY_SCORES[x.severity],
                    reverse=True,
                )[:10]
            ],
        }