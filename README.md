# SENTINEL — Threat Actor Intelligence Platform

> Personal threat intelligence platform tracking active threat actors, TTPs, and IOCs. RSS-ingested, LLM-enriched, updated every 4 hours via GitHub Actions.

**Live dashboard:** [jogit91.github.io/sentinel](https://jogit91.github.io/sentinel)

Built by [Jake Ouellette](https://jogit91.github.io) — Detection Engineer & Threat Intelligence Analyst

---

## What it does

- **Tracks 6+ active threat actors** with full profiles: TTPs (MITRE ATT&CK), targeted sectors, motivations, detection opportunities
- **Auto-ingests** from 15+ threat intelligence RSS feeds every 4 hours via GitHub Actions
- **LLM extraction** — Claude API extracts actor mentions, TTPs, IOCs, and sectors from new articles automatically
- **Attribution tool** — paste observables (technique IDs, sectors, malware names, IOC hints) and get ranked candidate actors with confidence scores
- **Activity trending** — 6-month mention history per actor with visual charts

## Architecture

```
RSS Feeds (15+ sources)
    ↓
GitHub Actions (every 4h)
    ↓
Python ingestor → Claude API extraction
    ↓
JSON data files (data/)
    ↓
GitHub Pages static dashboard (docs/)
```

No server. No database. No hosting costs. Pure static files + GitHub Actions.

## Tracked Actors

| Actor | Type | Activity Score |
|---|---|---|
| Qilin | Ransomware / RaaS | 98 |
| The Gentlemen | Ransomware / RaaS | 91 |
| ShinyHunters | Data Extortion | 85 |
| TeamPCP | Supply Chain | 79 |
| Salt Typhoon | APT / Nation-State | 76 |
| UNC6692 | Initial Access / Social Eng. | 72 |

## Setup

### 1. Fork this repository

### 2. Enable GitHub Pages
- Settings → Pages → Source: `Deploy from branch`
- Branch: `main`, folder: `/docs`

### 3. Add ANTHROPIC_API_KEY secret
- Settings → Secrets and variables → Actions → New repository secret
- Name: `ANTHROPIC_API_KEY`
- Value: your Anthropic API key

### 4. Enable GitHub Actions
The ingestor runs automatically every 4 hours. You can also trigger it manually from the Actions tab.

### 5. Update data URLs
In `docs/index.html` and `docs/actors.html`, replace `jogit91/sentinel` with your GitHub username/repo.

## Adding New Actors

Create a new JSON file in `data/actors/` following the schema in any existing profile. Add the actor ID to the `top_actors` array in `data/activity.json`.

## Local Development

```bash
# Serve docs/ locally
cd docs && python -m http.server 8080

# Test ingestor (requires ANTHROPIC_API_KEY env var)
cd ingestor && python feeds.py
```

## Data Sources

Threat intel feeds include: The DFIR Report, Huntress Blog, Red Canary, Bleeping Computer, Krebs on Security, CISA Advisories, Recorded Future, Mandiant, Unit 42, Microsoft Security Blog, MalwareBazaar, URLhaus

---

*SENTINEL is a personal project for threat intelligence research and skill development. All data sourced from public threat intelligence publications.*
