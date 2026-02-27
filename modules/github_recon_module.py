"""GitHub-Recon-Modul – sucht nach öffentlichen Repos und potenziellen Secret-Leaks."""

from __future__ import annotations

import re
from typing import Any

from core.models import Finding, Severity
from modules.base import BaseModule

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{16,}", "API-Key"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?.{6,}", "Passwort"),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]?[\w\-]{16,}", "Secret/Token"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(jdbc|mysql|postgres|mongodb):\/\/[^\s]+", "Datenbank-Verbindungsstring"),
]


class GithubReconModule(BaseModule):
    NAME = "github_recon"

    def __init__(self, domain: str, config: dict[str, Any]) -> None:
        super().__init__(domain, config)
        token = self.config.get("api_token", "")
        if token:
            self._session.headers["Authorization"] = f"token {token}"

    def collect(self) -> dict[str, Any]:
        org = self.domain.split(".")[0]
        self.logger.info(
            "GitHub-Suche für Organisation '%s' und Domain '%s'",
            org,
            self.domain,
        )

        code_results = self._search_code(self.domain)
        org_info = self._get_org(org)
        repos = self._get_repos(org) if org_info else []

        return {
            "organization": org_info,
            "public_repos": repos,
            "code_search_hits": code_results,
        }

    def _search_code(self, query: str) -> list[dict[str, Any]]:
        try:
            resp = self._get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 30},
                headers={
                    "Accept": "application/vnd.github.text-match+json",
                },
            )
            items = resp.json().get("items", [])
            results: list[dict[str, Any]] = []
            for item in items:
                # Text-Fragmente aus den text_matches extrahieren
                text_fragments = []
                for tm in item.get("text_matches", []):
                    fragment = tm.get("fragment", "")
                    if fragment:
                        text_fragments.append(fragment)

                results.append({
                    "repository": item["repository"]["full_name"],
                    "path": item["path"],
                    "url": item["html_url"],
                    "text_fragments": text_fragments,
                })
            return results
        except Exception as exc:
            self.logger.warning("GitHub Code-Suche fehlgeschlagen: %s", exc)
            return []

    def _get_org(self, org: str) -> dict[str, Any] | None:
        try:
            resp = self._get(f"https://api.github.com/orgs/{org}")
            data = resp.json()
            return {
                "name": data.get("name"),
                "public_repos": data.get("public_repos"),
                "blog": data.get("blog"),
                "email": data.get("email"),
                "description": data.get("description"),
            }
        except Exception:
            return None

    def _get_repos(self, org: str) -> list[dict[str, Any]]:
        try:
            resp = self._get(
                f"https://api.github.com/orgs/{org}/repos",
                params={"type": "public", "per_page": 100},
            )
            return [
                {
                    "name": r["full_name"],
                    "description": r.get("description"),
                    "language": r.get("language"),
                    "stars": r.get("stargazers_count"),
                    "url": r["html_url"],
                }
                for r in resp.json()
            ]
        except Exception as exc:
            self.logger.warning("GitHub Repo-Abfrage fehlgeschlagen: %s", exc)
            return []

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for hit in data.get("code_search_hits", []):
            # Prüfe sowohl Dateipfad als auch Textfragmente auf Secret-Muster
            searchable = hit.get("path", "")
            for fragment in hit.get("text_fragments", []):
                searchable += "\n" + fragment

            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, searchable):
                    findings.append(
                        Finding(
                            title=f"Potenzieller {label}-Leak auf GitHub",
                            description=(
                                f"Datei {hit['path']} in {hit['repository']} "
                                "enthält ein verdächtiges Muster."
                            ),
                            severity=Severity.HIGH,
                            source_module=self.NAME,
                            evidence={
                                "repository": hit.get("repository"),
                                "path": hit.get("path"),
                                "url": hit.get("url"),
                                "matched_pattern": label,
                            },
                            recommendations=[
                                "Repository prüfen und ggf. Secrets rotieren."
                            ],
                        )
                    )
                    break  # Ein Fund pro Datei reicht

        repos = data.get("public_repos", [])
        if repos:
            findings.append(
                Finding(
                    title=f"{len(repos)} öffentliche GitHub-Repositories gefunden",
                    description=(
                        "Öffentliche Repos können Quellcode, "
                        "Konfigurationen oder Secrets enthalten."
                    ),
                    severity=Severity.INFO,
                    source_module=self.NAME,
                    evidence={"repositories": repos[:20]},
                    recommendations=[
                        "Alle öffentlichen Repos auf versehentlich exponierte Secrets prüfen."
                    ],
                )
            )

        return findings