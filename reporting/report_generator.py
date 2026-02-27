"""Report-Generator – erzeugt JSON- und Textberichte."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analysis.risk_analyzer import RiskAnalyzer
from core.models import ScanResult


class ReportGenerator:
    """Generiert strukturierte Berichte."""

    def __init__(self, scan_result: ScanResult, config: dict[str, Any]) -> None:
        self.scan_result = scan_result
        self.config = config
        self.output_dir = Path(config.get("output_dir", "reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> list[str]:
        generated: list[str] = []
        formats = self.config.get("formats", ["json"])

        analyzer = RiskAnalyzer(self.scan_result)
        report_data = {
            "meta": {
                "tool": "OSINT-Scanner",
                "version": "1.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "disclaimer": (
                    "Dieser Bericht basiert ausschließlich auf öffentlich "
                    "zugänglichen Informationen. Es wurden keine aktiven "
                    "Scan- oder Angriffstechniken eingesetzt."
                ),
            },
            "risk_assessment": analyzer.summary(),
            "scan_result": self.scan_result.to_dict(),
        }

        if "json" in formats:
            path = self._write_json(report_data)
            generated.append(str(path))

        if "txt" in formats:
            path = self._write_text(report_data, analyzer)
            generated.append(str(path))

        return generated

    def _write_json(self, data: dict[str, Any]) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = (
            self.output_dir
            / f"osint_report_{self.scan_result.target_domain}_{ts}.json"
        )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        return path

    def _write_text(self, data: dict[str, Any], analyzer: RiskAnalyzer) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = (
            self.output_dir
            / f"osint_report_{self.scan_result.target_domain}_{ts}.txt"
        )
        lines = [
            "=" * 70,
            "  OSINT SICHERHEITSANALYSE – BERICHT",
            "=" * 70,
            f"  Ziel:            {self.scan_result.target_domain}",
            f"  Organisation:    {self.scan_result.target_organization}",
            f"  Scan-Start:      {self.scan_result.scan_start}",
            f"  Scan-Ende:       {self.scan_result.scan_end}",
            f"  Risikobewertung: {analyzer.risk_rating()} "
            f"({analyzer.calculate_risk_score()}/100)",
            f"  Gesamt-Findings: {len(self.scan_result.all_findings)}",
            "=" * 70,
            "",
        ]

        for mr in self.scan_result.module_results:
            lines.append(
                f"{'─' * 50}"
            )
            lines.append(
                f"  Modul: {mr.module_name.upper()} "
                f"(Status: {mr.status.value}, "
                f"Dauer: {mr.execution_time:.2f}s)"
            )
            lines.append(f"{'─' * 50}")

            if mr.errors:
                for err in mr.errors:
                    lines.append(f"  ❌ FEHLER: {err}")

            for f in mr.findings:
                sev = f.severity.value.upper()
                icon = {
                    "INFO": "ℹ️",
                    "LOW": "🟡",
                    "MEDIUM": "🟠",
                    "HIGH": "🔴",
                    "CRITICAL": "🚨",
                }.get(sev, "•")
                lines.append(f"  {icon} [{sev}] {f.title}")
                lines.append(f"     {f.description[:200]}")
                if f.recommendations:
                    lines.append("     Empfehlungen:")
                    for rec in f.recommendations:
                        lines.append(f"       → {rec}")
                lines.append("")

        lines.append("=" * 70)
        lines.append("  Ende des Berichts")
        lines.append("=" * 70)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path