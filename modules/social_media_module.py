"""Social-Media-Modul – ermittelt öffentliche Profile und Metadaten.

HINWEIS: Dieses Modul ist experimentell. Die Profilerkennung basiert auf
einfachen HTTP-Statuscode- und String-Heuristiken. Plattformen wie LinkedIn
blockieren häufig automatisierte Anfragen. Falsch-positive und
falsch-negative Ergebnisse sind wahrscheinlich. Ergebnisse sollten stets
manuell verifiziert werden.
"""

from __future__ import annotations

import re
from typing import Any

from core.models import Finding, Severity
from modules.base import BaseModule


# Plattform-Definitionen: Name → (URL-Template, Erfolgs-Check)
PLATFORM_CHECKS: dict[str, dict[str, str]] = {
    "github": {
        "url": "https://github.com/{slug}",
        "indicator": '="application/json"',
    },
    "twitter": {
        # Über die öffentliche Seite (kein API-Key nötig)
        "url": "https://nitter.net/{slug}",
        "indicator": "joined",
    },
    "linkedin": {
        "url": "https://www.linkedin.com/company/{slug}",
        "indicator": "LinkedIn",
    },
    "facebook": {
        "url": "https://www.facebook.com/{slug}",
        "indicator": "Facebook",
    },
    "instagram": {
        "url": "https://www.instagram.com/{slug}/",
        "indicator": "Instagram",
    },
    "youtube": {
        "url": "https://www.youtube.com/@{slug}",
        "indicator": "youtube",
    },
    "xing": {
        "url": "https://www.xing.com/pages/{slug}",
        "indicator": "XING",
    },
}


class SocialMediaModule(BaseModule):
    NAME = "social_media"

    def collect(self) -> dict[str, Any]:
        # Organisation-Slug aus Domain ableiten (z. B. "example" aus "example.com")
        slug = self.domain.split(".")[0].lower()
        org_name = slug.replace("-", "").replace("_", "")

        platforms = self.config.get(
            "platforms",
            ["github", "twitter", "linkedin", "facebook", "instagram"],
        )

        self.logger.info(
            "Social-Media-Suche für '%s' auf %d Plattformen",
            slug,
            len(platforms),
        )

        results: dict[str, dict[str, Any]] = {}
        # Mehrere Slug-Varianten testen
        slug_variants = list({slug, org_name})

        for platform in platforms:
            if platform not in PLATFORM_CHECKS:
                self.logger.warning(
                    "Unbekannte Plattform '%s' – überspringe.", platform
                )
                continue

            pconfig = PLATFORM_CHECKS[platform]
            found = False

            for variant in slug_variants:
                url = pconfig["url"].format(slug=variant)
                try:
                    resp = self._session.get(
                        url,
                        timeout=self.config.get("timeout", 10),
                        allow_redirects=True,
                    )
                    # Heuristik: Profil existiert, wenn Status 200
                    # und ein plattform-spezifisches Keyword vorhanden ist
                    exists = (
                        resp.status_code == 200
                        and pconfig["indicator"].lower()
                        in resp.text[:10_000].lower()
                    )

                    if exists:
                        results[platform] = {
                            "exists": True,
                            "url": str(resp.url),
                            "slug_used": variant,
                            "status_code": resp.status_code,
                            "meta": self._extract_meta(resp.text),
                        }
                        found = True
                        break
                except Exception as exc:
                    self.logger.debug(
                        "Social-Media-Check %s/%s fehlgeschlagen: %s",
                        platform,
                        variant,
                        exc,
                    )

            if not found:
                results[platform] = {"exists": False, "url": "", "slug_used": slug}

        # Zusätzlich: Google-Suche nach Social-Media-Profilen
        google_profiles = self._google_social_search(slug)

        return {
            "platform_results": results,
            "google_discovered_profiles": google_profiles,
            "slug_variants_tested": slug_variants,
        }

    def _extract_meta(self, html: str) -> dict[str, str]:
        """Extrahiert grundlegende Meta-Tags aus dem HTML."""
        meta: dict[str, str] = {}
        # og:title
        match = re.search(
            r'<meta\s+property="og:title"\s+content="([^"]+)"',
            html[:5000],
            re.IGNORECASE,
        )
        if match:
            meta["og_title"] = match.group(1)

        # og:description
        match = re.search(
            r'<meta\s+property="og:description"\s+content="([^"]+)"',
            html[:5000],
            re.IGNORECASE,
        )
        if match:
            meta["og_description"] = match.group(1)

        # Follower/Mitarbeiter (generisch)
        match = re.search(r"([\d,.]+)\s*(followers|Follower)", html[:20_000], re.I)
        if match:
            meta["followers"] = match.group(1)

        return meta

    def _google_social_search(self, slug: str) -> list[dict[str, str]]:
        """Versucht über eine einfache Suche weitere Profile zu finden."""
        profiles: list[dict[str, str]] = []
        try:
            query = f'"{self.domain}" OR "{slug}" site:linkedin.com OR site:twitter.com OR site:github.com'
            resp = self._get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
            )
            # Einfaches Link-Parsing
            links = re.findall(r'href="(https?://[^"]+)"', resp.text)
            social_domains = [
                "linkedin.com",
                "twitter.com",
                "github.com",
                "facebook.com",
                "instagram.com",
                "xing.com",
            ]
            seen: set[str] = set()
            for link in links:
                for sd in social_domains:
                    if sd in link and link not in seen:
                        seen.add(link)
                        profiles.append({"platform": sd, "url": link})
        except Exception as exc:
            self.logger.debug("DuckDuckGo Social-Suche fehlgeschlagen: %s", exc)

        return profiles

    # ------------------------------------------------------------------ #

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        results = data.get("platform_results", {})

        existing_profiles = {
            p: info for p, info in results.items() if info.get("exists")
        }
        missing_profiles = {
            p: info for p, info in results.items() if not info.get("exists")
        }

        if existing_profiles:
            profile_urls = {
                p: info["url"] for p, info in existing_profiles.items()
            }
            findings.append(
                Finding(
                    title=(
                        f"{len(existing_profiles)} Social-Media-Profile gefunden"
                    ),
                    description=(
                        "Folgende öffentliche Profile wurden identifiziert. "
                        "Diese können für Social Engineering oder "
                        "Informationsgewinnung genutzt werden."
                    ),
                    severity=Severity.INFO,
                    source_module=self.NAME,
                    evidence={
                        "profiles": profile_urls,
                        "metadata": {
                            p: info.get("meta", {})
                            for p, info in existing_profiles.items()
                        },
                    },
                    recommendations=[
                        "Social-Media-Richtlinien für Mitarbeiter etablieren.",
                        "Überprüfen, welche Unternehmensinformationen öffentlich "
                        "auf Social Media geteilt werden.",
                    ],
                )
            )

        # Marken-Squatting-Risiko
        if missing_profiles:
            findings.append(
                Finding(
                    title=(
                        f"Kein Profil auf {len(missing_profiles)} "
                        f"Plattform(en) gefunden"
                    ),
                    description=(
                        "Auf folgenden Plattformen wurde kein offizielles "
                        "Profil gefunden: "
                        + ", ".join(missing_profiles.keys())
                        + ". Dies birgt ein Risiko für Marken-Squatting."
                    ),
                    severity=Severity.LOW,
                    source_module=self.NAME,
                    evidence={
                        "unclaimed_platforms": list(missing_profiles.keys())
                    },
                    recommendations=[
                        "Proaktiv Accounts auf relevanten Plattformen sichern.",
                        "Regelmäßig nach Fake-Profilen suchen.",
                    ],
                )
            )

        # Zusätzlich entdeckte Profile
        google_profiles = data.get("google_discovered_profiles", [])
        if google_profiles:
            findings.append(
                Finding(
                    title=(
                        f"{len(google_profiles)} weitere Profile via "
                        "Suchmaschine entdeckt"
                    ),
                    description=(
                        "Über eine DuckDuckGo-Suche wurden zusätzliche "
                        "Social-Media-Referenzen gefunden."
                    ),
                    severity=Severity.INFO,
                    source_module=self.NAME,
                    evidence={"discovered_profiles": google_profiles[:20]},
                    recommendations=[],
                )
            )

        return findings