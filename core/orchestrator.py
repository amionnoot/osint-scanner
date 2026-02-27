"""Orchestrator – koordiniert die Modulausführung."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from core.config import Config
from core.models import ModuleResult, ModuleStatus, ScanResult
from modules.whois_module import WhoisModule
from modules.dns_module import DnsModule
from modules.ct_logs_module import CtLogsModule
from modules.tech_fingerprint_module import TechFingerprintModule
from modules.email_harvest_module import EmailHarvestModule
from modules.github_recon_module import GithubReconModule
from modules.shodan_passive_module import ShodanPassiveModule
from modules.breach_check_module import BreachCheckModule
from modules.social_media_module import SocialMediaModule
from modules.google_dorking_module import GoogleDorkingModule
from modules.pastebin_monitor_module import PastebinMonitorModule
from reporting.report_generator import ReportGenerator

# Registry: Modulname → Klasse
MODULE_REGISTRY: dict[str, type] = {
    "whois": WhoisModule,
    "dns": DnsModule,
    "ct_logs": CtLogsModule,
    "tech_fingerprint": TechFingerprintModule,
    "email_harvest": EmailHarvestModule,
    "github_recon": GithubReconModule,
    "shodan_passive": ShodanPassiveModule,
    "breach_check": BreachCheckModule,
    "social_media": SocialMediaModule,
    "google_dorking": GoogleDorkingModule,
    "pastebin_monitor": PastebinMonitorModule,
}


class Orchestrator:
    """Steuert den gesamten Scan-Ablauf."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger("osint_scanner.orchestrator")

    def run(self) -> ScanResult:
        domain = self.config.target_domain
        org = self.config.target_organization
        self.logger.info("Starte OSINT-Scan für %s (%s)", domain, org)

        result = ScanResult(target_domain=domain, target_organization=org)

        for name, cls in MODULE_REGISTRY.items():
            if not self.config.is_module_enabled(name):
                self.logger.info("Modul '%s' deaktiviert – überspringe.", name)
                result.module_results.append(
                    ModuleResult(module_name=name, status=ModuleStatus.SKIPPED)
                )
                continue

            module_config = self.config.module_config(name)
            # Rate-Limiting-Parameter aus globaler Config in Modul-Config einmischen
            rate_cfg = self.config.rate_limit
            for key in ("requests_per_second", "retry_attempts", "retry_delay"):
                if key in rate_cfg and key not in module_config:
                    module_config[key] = rate_cfg[key]
            module = cls(domain=domain, config=module_config)
            module_result = module.run()
            result.module_results.append(module_result)

        result.scan_end = datetime.now(timezone.utc).isoformat()
        self.logger.info(
            "Scan abgeschlossen – %d Ergebnisse gesamt",
            len(result.all_findings),
        )

        # Report generieren
        reporter = ReportGenerator(result, self.config.reporting_config)
        paths = reporter.generate()
        for p in paths:
            self.logger.info("Bericht erstellt: %s", p)

        return result