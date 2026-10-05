# Specula

**Specula** is a modular platform for threat and exposure intelligence.

| Module | Status |
|--------|--------|
| **Specula Threat** – Threat Intelligence | In development (MVP) |
| Specula Exposure | Planned |
| Specula Third Party | Planned |
| Specula OSINT | Planned |
| Specula CLOSINT | Planned |

## Specula Threat

Specula Threat collects, normalizes and correlates data from public and authenticated threat intelligence sources and presents it in a dashboard for a team of analysts. It answers three questions:

1. **What is happening right now?** Global dashboard and intel feed.
2. **What should I prioritize?** Vulnerabilities that are exploited or likely to be exploited, ranked by priority levels P1–P4.
3. **What affects my perimeter?** Dashboards by vendor, country, sector, ransomware group and malware family.

It performs no active scanning.

**MVP sources:** NVD, CISA KEV, EPSS, ransomware.live (PRO API), abuse.ch, AlienVault OTX, CSIRT Italia.

**Stack:** API-first Python backend (FastAPI), plugin-based collectors, PostgreSQL, React frontend, Docker Compose deployment on a Linux VM.

## Project status

The project is in phase **M0** of the [implementation plan](docs/piano-implementazione.md): documentation approved, no code released yet.

## Documentation

The project documentation is written in Italian.

- [Functional specification](docs/specifica-funzionale-dashboard.md)
- [Architecture](docs/architettura.md)
- [Implementation plan](docs/piano-implementazione.md)
- [Visual identity and design tokens](docs/identita-visiva.md)
- [Project rules for Claude Code](CLAUDE.md)

## OSINT Toolkit (previous version)

This repository previously contained **OSINT Toolkit**, a set of bash scripts for domain reconnaissance. Those scripts are not part of Specula and have been removed. The last version is preserved in the [`legacy-final`](https://github.com/sandrosana/specula-platform/tree/legacy-final) tag.

## License

[MIT](LICENSE) – © 2025-2026 Sandro Sana
