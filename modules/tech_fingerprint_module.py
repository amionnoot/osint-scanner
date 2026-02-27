"""Technologie-Fingerprinting – erkennt Technologien über HTTP-Header und HTML.

HINWEIS: Dieses Modul ist *minimal-invasiv*. Es führt einen einzelnen
HTTP-GET-Request gegen die Ziel-Domain aus (vergleichbar mit einem normalen
Browser-Aufruf). Es findet kein Port-Scanning, kein Crawling geschützter
Bereiche und kein aktives Probing statt.
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from core.models import Finding, Severity
from modules.base import BaseModule

HEADER_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "Server": [
        (r"Apache[\/ ]?([\d.]+)?", "Apache"),
        (r"nginx[\/ ]?([\d.]+)?", "Nginx"),
        (r"Microsoft-IIS[\/ ]?([\d.]+)?", "Microsoft IIS"),
        (r"LiteSpeed", "LiteSpeed"),
        (r"cloudflare", "Cloudflare"),
    ],
    "X-Powered-By": [
        (r"PHP[\/ ]?([\d.]+)?", "PHP"),
        (r"ASP\.NET", "ASP.NET"),
        (r"Express", "Express.js / Node.js"),
        (r"Next\.js", "Next.js"),
    ],
}


class TechFingerprintModule(BaseModule):
    NAME = "tech_fingerprint"

    def collect(self) -> dict[str, Any]:
        url = f"https://{self.domain}"
        self.logger.info("HTTP-Header und HTML-Analyse für %s", url)

        resp = self._get(url, allow_redirects=True)
        headers = dict(resp.headers)
        html = resp.text[:50_000]

        techs = self._detect_from_headers(headers)
        techs.update(self._detect_from_html(html))
        security_headers = self._check_security_headers(headers)

        return {
            "url": str(resp.url),
            "status_code": resp.status_code,
            "detected_technologies": sorted(techs),
            "security_headers": security_headers,
            "raw_headers": headers,
        }

    @staticmethod
    def _detect_from_headers(headers: dict[str, str]) -> set[str]:
        found: set[str] = set()
        for header, patterns in HEADER_SIGNATURES.items():
            value = headers.get(header, "")
            for pattern, tech in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    found.add(tech)
        return found

    @staticmethod
    def _detect_from_html(html: str) -> set[str]:
        found: set[str] = set()
        soup = BeautifulSoup(html, "html.parser")

        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            found.add(f"Generator: {gen['content']}")

        patterns = {
            r"react": "React",
            r"vue\.?js": "Vue.js",
            r"angular": "Angular",
            r"jquery": "jQuery",
            r"bootstrap": "Bootstrap",
            r"wp-content|wp-includes": "WordPress",
        }
        for pattern, tech in patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                found.add(tech)

        return found

    @staticmethod
    def _check_security_headers(headers: dict[str, str]) -> dict[str, str | None]:
        important = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        return {h: headers.get(h) for h in important}

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        sec_headers = data.get("security_headers", {})
        missing = [h for h, v in sec_headers.items() if v is None]
        if missing:
            findings.append(
                Finding(
                    title="Fehlende HTTP-Security-Header",
                    description=(
                        "Folgende empfohlene Security-Header fehlen: "
                        + ", ".join(missing)
                    ),
                    severity=Severity.MEDIUM,
                    source_module=self.NAME,
                    evidence={"missing_headers": missing},
                    recommendations=[
                        "Strict-Transport-Security (HSTS) mit langer max-age setzen.",
                        "Content-Security-Policy definieren.",
                        "X-Content-Type-Options: nosniff aktivieren.",
                    ],
                )
            )

        raw = data.get("raw_headers", {})
        server = raw.get("Server", "")
        if re.search(r"[\d.]+", server):
            findings.append(
                Finding(
                    title="Server-Versionsinfo in HTTP-Headern exponiert",
                    description=f"Der Server-Header verrät die Version: '{server}'.",
                    severity=Severity.LOW,
                    source_module=self.NAME,
                    evidence={"server_header": server},
                    recommendations=[
                        "Server-Header so konfigurieren, dass keine "
                        "Versionsnummern preisgegeben werden."
                    ],
                )
            )

        techs = data.get("detected_technologies", [])
        if techs:
            findings.append(
                Finding(
                    title="Erkannte Technologien",
                    description="Folgende Technologien wurden passiv identifiziert.",
                    severity=Severity.INFO,
                    source_module=self.NAME,
                    evidence={"technologies": techs},
                    recommendations=[],
                )
            )

        return findings