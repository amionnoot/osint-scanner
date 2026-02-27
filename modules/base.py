"""Abstrakte Basisklasse für alle OSINT-Module."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import requests

from core.models import ModuleResult, ModuleStatus


class BaseModule(ABC):
    """Jedes Modul erbt von dieser Klasse."""

    NAME: str = "base"

    def __init__(self, domain: str, config: dict[str, Any]) -> None:
        self.domain = domain
        self.config = config
        self.logger = logging.getLogger(f"osint_scanner.{self.NAME}")
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        )
        # Rate-Limiting-Parameter (können via global config überschrieben werden)
        self._request_delay: float = 1.0 / max(
            config.get("requests_per_second", 2), 0.1
        )
        self._retry_attempts: int = int(config.get("retry_attempts", 3))
        self._retry_delay: float = float(config.get("retry_delay", 5))

    # -- Hilfsmethoden ---------------------------------------------------- #

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP-GET mit Fehlerhandling, Retry-Logik und Rate-Limiting."""
        timeout = kwargs.pop("timeout", self.config.get("timeout", 10))
        time.sleep(self._request_delay)

        last_exc: Exception | None = None
        for attempt in range(1, self._retry_attempts + 1):
            try:
                resp = self._session.get(url, timeout=timeout, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.exceptions.HTTPError as exc:
                # Nicht retrybar bei Client-Fehlern (4xx) außer 429
                if exc.response is not None and 400 <= exc.response.status_code < 500:
                    if exc.response.status_code == 429:
                        self.logger.warning(
                            "Rate-Limit erreicht (429), warte %ss (Versuch %d/%d)",
                            self._retry_delay,
                            attempt,
                            self._retry_attempts,
                        )
                        time.sleep(self._retry_delay)
                        last_exc = exc
                        continue
                    raise
                last_exc = exc
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc

            if attempt < self._retry_attempts:
                self.logger.warning(
                    "Request fehlgeschlagen (%s), Retry %d/%d in %ss",
                    last_exc,
                    attempt,
                    self._retry_attempts,
                    self._retry_delay,
                )
                time.sleep(self._retry_delay)

        # Alle Versuche fehlgeschlagen
        raise last_exc  # type: ignore[misc]

    def _safe_json(self, resp: requests.Response) -> Any:
        """JSON-Parsing mit Fehlertoleranz."""
        try:
            return resp.json()
        except Exception:
            return {}

    # -- Pflichtmethoden -------------------------------------------------- #

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Daten sammeln – gibt ein Rohdict zurück."""
        ...

    @abstractmethod
    def analyze(self, data: dict[str, Any]) -> list[Any]:
        """Daten analysieren – gibt eine Liste von Findings zurück."""
        ...

    # -- Ausführung ------------------------------------------------------- #

    def run(self) -> ModuleResult:
        """Führt collect → analyze aus und liefert ein ModuleResult."""
        start = time.time()
        try:
            self.logger.info(
                "Starte Modul '%s' für %s", self.NAME, self.domain
            )
            data = self.collect()
            findings = self.analyze(data)
            elapsed = time.time() - start
            self.logger.info(
                "Modul '%s' abgeschlossen – %d Fund(e) in %.2fs",
                self.NAME,
                len(findings),
                elapsed,
            )
            return ModuleResult(
                module_name=self.NAME,
                status=ModuleStatus.SUCCESS,
                data=data,
                findings=findings,
                execution_time=elapsed,
            )
        except Exception as exc:
            elapsed = time.time() - start
            self.logger.error("Modul '%s' fehlgeschlagen: %s", self.NAME, exc)
            return ModuleResult(
                module_name=self.NAME,
                status=ModuleStatus.FAILED,
                errors=[str(exc)],
                execution_time=elapsed,
            )