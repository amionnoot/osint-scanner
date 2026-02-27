#!/usr/bin/env python3
"""
OSINT-Scanner – Passives Sicherheitsanalyse-Tool v1.1

Nutzung:
    python main.py                          # Standard-Konfiguration
    python main.py -c custom_config.yaml    # Eigene Konfiguration
    python main.py -d example.com           # Domain überschreiben
    python main.py -d example.com -v        # Verbose-Modus
    python main.py --json-stdout            # JSON auf stdout
    python main.py --list-modules           # Verfügbare Module auflisten
"""

from __future__ import annotations

import argparse
import json
import sys

from core.config import Config
from core.logger import setup_logger
from core.orchestrator import Orchestrator, MODULE_REGISTRY
from analysis.risk_analyzer import RiskAnalyzer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OSINT-Scanner – Passive Sicherheitsanalyse v1.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  python main.py -d example.com\n"
            "  python main.py -d example.com -v --json-stdout\n"
            "  python main.py -c config.local.yaml -o ./my-reports\n"
            "  python main.py --list-modules\n"
        ),
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Pfad zur Konfigurationsdatei (Standard: config.yaml)",
    )
    parser.add_argument(
        "-d", "--domain",
        help="Ziel-Domain (überschreibt Konfiguration)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Ausgabeverzeichnis für Berichte",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Ausführliches Logging (DEBUG-Level)",
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="JSON-Zusammenfassung auf stdout ausgeben",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="Verfügbare Module auflisten und beenden",
    )
    return parser.parse_args()


def list_modules() -> None:
    """Gibt alle registrierten Module aus."""
    print("\n📦 Verfügbare OSINT-Module:\n")
    print(f"  {'Name':<25} {'Klasse':<35}")
    print(f"  {'─' * 25} {'─' * 35}")
    for name, cls in MODULE_REGISTRY.items():
        print(f"  {name:<25} {cls.__name__:<35}")
    print(f"\n  Gesamt: {len(MODULE_REGISTRY)} Module\n")


def main() -> int:
    args = parse_args()

    if args.list_modules:
        list_modules()
        return 0

    # Konfiguration laden
    try:
        config = Config(args.config)
    except FileNotFoundError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1

    # CLI-Überschreibungen
    if args.domain:
        config._data.setdefault("target", {})["domain"] = args.domain
    if args.output:
        config._data.setdefault("reporting", {})["output_dir"] = args.output
    if args.verbose:
        config._data.setdefault("logging", {})["level"] = "DEBUG"

    if not config.target_domain:
        print(
            "FEHLER: Keine Ziel-Domain angegeben. "
            "Verwende -d <domain> oder setze target.domain in der config.yaml.",
            file=sys.stderr,
        )
        return 1

    # Logger einrichten
    logger = setup_logger(config.logging_config)

    banner = r"""
    ╔═══════════════════════════════════════════════════╗
    ║       🔍 OSINT-Scanner v1.1                      ║
    ║       Passive Sicherheitsanalyse                  ║
    ║       Nur öffentlich zugängliche Quellen          ║
    ╚═══════════════════════════════════════════════════╝
    """
    logger.info(banner)
    logger.info("Ziel-Domain:      %s", config.target_domain)
    logger.info("Organisation:     %s", config.target_organization)
    logger.info("Konfiguration:    %s", args.config)

    # Scan ausführen
    orchestrator = Orchestrator(config)
    scan_result = orchestrator.run()

    # Risikobewertung
    analyzer = RiskAnalyzer(scan_result)
    summary = analyzer.summary()

    logger.info("─" * 60)
    logger.info(
        "Risikobewertung: %s (Score: %s/100)",
        summary["risk_rating"],
        summary["risk_score"],
    )
    logger.info("Gesamt-Findings:  %d", summary["total_findings"])
    for sev, count in summary["findings_by_severity"].items():
        if count > 0:
            logger.info("  %-12s: %d", sev.upper(), count)
    logger.info("─" * 60)

    if args.json_stdout:
        print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
