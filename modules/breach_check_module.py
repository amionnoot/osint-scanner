"""Breach-Check-Modul – prüft E-Mail-Adressen gegen HaveIBeenPwned."""

from __future__ import annotations

import time
from typing import Any

from core.models import Finding, Severity
from modules.base import BaseModule


class BreachCheckModule(BaseModule):
    NAME = "breach_check"

    HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self, domain: str, config: dict[str, Any]) -> None:
        super().__init__(domain, config)
        api_key = self.config.get("hibp_api_key", "")
        if api_key:
            self._session.headers["hibp-api-key"] = api_key
        self._session.headers["User-Agent"] = "OSINT-Scanner/1.0"
        self._delay = float(self.config.get("request_delay", 2.0))

    # ------------------------------------------------------------------ #
    #  Datensammlung                                                      #
    # ------------------------------------------------------------------ #

    def collect(self) -> dict[str, Any]:
        has_api_key = bool(self.config.get("hibp_api_key", ""))
        source = "haveibeenpwned" if has_api_key else "haveibeenpwned_public"

        if not has_api_key:
            self.logger.warning(
                "Kein HIBP-API-Key konfiguriert – "
                "nur öffentliche Breach-Liste verfügbar "
                "(keine E-Mail-Einzelprüfung möglich)."
            )

        self.logger.info(
            "HIBP Domain-Breach-Suche für %s (Quelle: %s)",
            self.domain,
            source,
        )

        # Domain-weite Breach-Suche (funktioniert auch ohne API-Key)
        domain_breaches = self._hibp_domain_search()

        return {
            "source": source,
            "domain_breaches": domain_breaches,
            "email_results": [],
        }

    def _hibp_domain_search(self) -> list[dict[str, Any]]:
        """Alle bekannten Breaches abrufen und nach Domain filtern.

        Der /breaches-Endpunkt ist öffentlich und benötigt keinen API-Key.
        """
        try:
            resp = self._get(f"{self.HIBP_API_BASE}/breaches")
            all_breaches = resp.json()
            return [
                {
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified"),
                    "description": b.get("Description", "")[:300],
                }
                for b in all_breaches
                if self.domain.lower() in (b.get("Domain") or "").lower()
            ]
        except Exception as exc:
            self.logger.warning("HIBP Domain-Suche fehlgeschlagen: %s", exc)
            return []

    def check_single_email(self, email: str) -> list[dict[str, Any]]:
        """Prüft eine einzelne E-Mail-Adresse gegen HIBP (benötigt API-Key)."""
        api_key = self.config.get("hibp_api_key", "")
        if not api_key:
            self.logger.warning(
                "E-Mail-Einzelprüfung erfordert einen HIBP-API-Key."
            )
            return []
        try:
            time.sleep(self._delay)
            resp = self._get(
                f"{self.HIBP_API_BASE}/breachedaccount/{email}",
                params={"truncateResponse": "false"},
            )
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  Analyse                                                            #
    # ------------------------------------------------------------------ #

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        domain_breaches = data.get("domain_breaches", [])
        if domain_breaches:
            total_accounts = sum(
                b.get("pwn_count", 0) for b in domain_breaches
            )
            all_data_classes: set[str] = set()
            for b in domain_breaches:
                all_data_classes.update(b.get("data_classes", []))

            findings.append(
                Finding(
                    title=(
                        f"Domain in {len(domain_breaches)} "
                        f"Datenleck(s) gefunden"
                    ),
                    description=(
                        f"Die Domain {self.domain} taucht in "
                        f"{len(domain_breaches)} bekannten Breaches auf. "
                        f"Insgesamt ca. {total_accounts:,} betroffene Accounts. "
                        f"Exponierte Datentypen: "
                        f"{', '.join(sorted(all_data_classes))}"
                    ),
                    severity=Severity.CRITICAL
                    if total_accounts > 100_000
                    else Severity.HIGH,
                    source_module=self.NAME,
                    evidence={
                        "breaches": domain_breaches,
                        "total_affected_accounts": total_accounts,
                        "exposed_data_types": sorted(all_data_classes),
                    },
                    recommendations=[
                        "Alle betroffenen Accounts zur Passwort-Änderung auffordern.",
                        "MFA für alle Dienste erzwingen.",
                        "Credential-Monitoring implementieren.",
                        "Prüfen, ob interne Passwörter in Breaches enthalten sind.",
                    ],
                )
            )

            # Einzelne Breaches auflisten
            for breach in domain_breaches:
                findings.append(
                    Finding(
                        title=f"Breach: {breach.get('title', 'Unbekannt')}",
                        description=(
                            f"Datum: {breach.get('breach_date', 'n/a')} – "
                            f"Betroffene: {breach.get('pwn_count', 'n/a'):,} – "
                            f"Daten: {', '.join(breach.get('data_classes', []))}"
                        ),
                        severity=Severity.MEDIUM,
                        source_module=self.NAME,
                        evidence=breach,
                        recommendations=[],
                    )
                )

        # E-Mail-spezifische Ergebnisse
        email_results = data.get("email_results", [])
        for er in email_results:
            email = er.get("email", "unbekannt")
            breaches = er.get("breaches", [])
            if breaches:
                findings.append(
                    Finding(
                        title=f"E-Mail {email} in {len(breaches)} Breach(es)",
                        description=(
                            f"Die Adresse {email} wurde in folgenden "
                            f"Breaches gefunden: "
                            f"{', '.join(b.get('Name', '?') for b in breaches)}"
                        ),
                        severity=Severity.HIGH,
                        source_module=self.NAME,
                        evidence={"email": email, "breaches": breaches},
                        recommendations=[
                            f"Passwort für {email} sofort ändern.",
                            "MFA aktivieren.",
                        ],
                    )
                )

        if not domain_breaches and not email_results:
            findings.append(
                Finding(
                    title="Keine Breaches für die Domain gefunden",
                    description=(
                        f"In den geprüften Quellen wurden keine bekannten "
                        f"Datenlecks für {self.domain} identifiziert."
                    ),
                    severity=Severity.INFO,
                    source_module=self.NAME,
                    evidence={},
                    recommendations=[
                        "Regelmäßig erneut prüfen – neue Breaches werden "
                        "kontinuierlich veröffentlicht."
                    ],
                )
            )

        return findings