"""WHOIS-Modul – liest öffentliche Registrierungsdaten aus."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

import whois

from core.models import Finding, Severity
from modules.base import BaseModule


class WhoisModule(BaseModule):
    NAME = "whois"

    def collect(self) -> dict[str, Any]:
        self.logger.info("WHOIS-Abfrage für %s", self.domain)
        w = whois.whois(self.domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers or [],
            "dnssec": getattr(w, "dnssec", None),
            "registrant": w.get("name"),
            "org": w.get("org"),
            "emails": w.emails or [],
            "country": w.get("country"),
        }

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        # WHOIS-Privacy fehlt
        emails = data.get("emails") or []
        personal_emails = [
            e
            for e in emails
            if not any(
                kw in e.lower()
                for kw in ("privacy", "proxy", "redacted", "whoisguard")
            )
        ]
        if personal_emails:
            findings.append(
                Finding(
                    title="WHOIS-Datenschutz nicht aktiviert",
                    description=(
                        "Die Domain veröffentlicht personenbezogene E-Mail-Adressen "
                        "in den WHOIS-Daten. Angreifer könnten diese für gezielte "
                        "Phishing-Angriffe verwenden."
                    ),
                    severity=Severity.MEDIUM,
                    source_module=self.NAME,
                    evidence={"exposed_emails": personal_emails},
                    recommendations=[
                        "WHOIS-Privacy / Domain-Privacy beim Registrar aktivieren.",
                        "Prüfen, ob exponierte Adressen in Breach-Datenbanken auftauchen.",
                    ],
                )
            )

        # Domain läuft bald ab
        exp_raw = data.get("expiration_date", "")
        match = re.search(r"\d{4}-\d{2}-\d{2}", str(exp_raw))
        if match:
            exp_date = datetime.strptime(match.group(), "%Y-%m-%d")
            if exp_date - datetime.now(timezone.utc).replace(tzinfo=None) < timedelta(days=90):
                findings.append(
                    Finding(
                        title="Domain läuft in weniger als 90 Tagen ab",
                        description=(
                            f"Die Domain {self.domain} läuft am {exp_date.date()} ab. "
                            "Ein Ablauf könnte zu Domain-Hijacking führen."
                        ),
                        severity=Severity.HIGH,
                        source_module=self.NAME,
                        evidence={"expiration_date": str(exp_date.date())},
                        recommendations=[
                            "Domain-Verlängerung umgehend veranlassen."
                        ],
                    )
                )

        return findings