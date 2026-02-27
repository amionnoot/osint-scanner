# 🔍 OSINT-Scanner – Passives Sicherheitsanalyse-Tool

Ein modulares, rein passives OSINT-Analyse-Tool für professionelle Sicherheitsrecherchen.
Es sammelt ausschließlich öffentlich zugängliche Informationen und setzt **keine aktiven
Scan- oder Angriffstechniken** ein.

## ⚠️ Rechtlicher Hinweis

Dieses Tool darf nur für **autorisierte Sicherheitsanalysen** eingesetzt werden.
Stellen Sie sicher, dass Sie eine schriftliche Genehmigung des Zielunternehmens besitzen
oder ausschließlich eigene Domains analysieren. Der Autor übernimmt keine Haftung für
missbräuchliche Verwendung.

## 🚀 Schnellstart

```bash
# Repository klonen
git clone <repo-url> osint-scanner
cd osint-scanner

# Virtuelle Umgebung erstellen
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Abhängigkeiten installieren
pip install -r requirements.txt

# Konfiguration anpassen
cp config.yaml config.local.yaml
# config.local.yaml bearbeiten → Ziel-Domain eintragen

# Scan starten
python main.py
python main.py -d example.com
python main.py -d example.com -v --json-stdout
```

## 📦 Module

| Modul | Beschreibung | Quelle |
|---|---|---|
| `whois` | WHOIS-Registrierungsdaten | WHOIS-Server |
| `dns` | DNS-Records, SPF, DMARC | DNS-Resolver |
| `ct_logs` | Subdomains via Certificate Transparency | crt.sh |
| `tech_fingerprint` | Technologie-Erkennung via Header/HTML | HTTP-Response |
| `email_harvest` | Öffentliche E-Mail-Adressen | crt.sh, PGP-Keyserver |
| `github_recon` | GitHub-Repos, Code-Leaks | GitHub API |
| `shodan_passive` | Passiv indexierte Dienste/CVEs | Shodan API |
| `breach_check` | E-Mails in Breach-Datenbanken | HaveIBeenPwned API |
| `social_media` | Social-Media-Profile & Metadaten | Öffentliche APIs |
| `google_dorking` | Suchmaschinen-basierte Aufklärung | Google Custom Search |
| `pastebin_monitor` | Erwähnungen in Paste-Diensten | Öffentliche Paste-APIs |

## 🔧 Konfiguration

Alle Einstellungen in `config.yaml`. API-Keys für optionale Module:

- **Shodan**: [shodan.io](https://shodan.io) → API-Key
- **HaveIBeenPwned**: [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
- **Google Custom Search**: [Google CSE](https://programmablesearchengine.google.com/)

## 📊 Ausgabe

Berichte werden als JSON im `reports/`-Verzeichnis gespeichert. Jeder Bericht enthält:
- Metadaten & Disclaimer
- Risikobewertung (Score 0–100)
- Einzelergebnisse pro Modul mit Severity-Bewertung
- Handlungsempfehlungen

## 🏗 Architektur

```
CLI → Orchestrator → [Module] → Analyse-Engine → Report-Generator
                         ↓
                   BaseModule (abstrakt)
                   ├── collect()   → Rohdaten
                   └── analyze()   → Findings
```
