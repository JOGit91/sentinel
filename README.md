# SENTINEL — Threat Actor Intelligence Platform

> Personal threat intelligence platform tracking active threat actors, TTPs, and IOCs. RSS-ingested, LLM-enriched, updated every 4 hours via GitHub Actions.

**Live dashboard:** [JOGit91.github.io/sentinel](https://JOGit91.github.io/sentinel)

Built by [Jake Ouellette](https://jogit91.github.io) — Detection Engineer & Threat Intelligence Analyst

---

## What it does

- **Tracks 6+ active threat actors** with full profiles: TTPs (MITRE ATT&CK), targeted sectors, motivations, detection opportunities
- **Auto-ingests** from 15+ threat intelligence RSS feeds every 4 hours via GitHub Actions
- **LLM extraction** — Claude API extracts actor mentions, TTPs, IOCs, and sectors from new articles automatically
- **Attribution tool** — paste observables (technique IDs, sectors, malware names, IOC hints) and get ranked candidate actors with confidence scores
- **Org Risk Profile** — describe your vertical, cloud/business services, hardware stack, and special cases to get likely threat actors, trending tactics, recommended threat hunts, and prioritized mitigations, with links to further reading and recent coverage
- **Activity trending** — 6-month mention history per actor with visual charts
- **Tactics & Tools on the Rise** — tracks trending TTPs, malware, and exploits (e.g. ClickFix, EDR Silencers, Shai-Hulud, Lumma Stealer) independent of actor attribution, cross-linked to related actor profiles

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
| EvilTokens | Initial Access / PhaaS | 90 |
| APT28 | APT / Nation-State | 88 |
| ShinyHunters | Data Extortion | 85 |
| Lazarus Group | APT / Nation-State | 84 |
| Silver Fox | APT / China-Nexus | 81 |
| Turla | APT / Nation-State | 81 |
| Gamaredon | APT / Nation-State | 80 |
| TeamPCP | Supply Chain | 79 |
| APT38 | APT / Nation-State | 78 |
| Mustang Panda | APT / Nation-State | 78 |
| Salt Typhoon | APT / Nation-State | 76 |
| Akira | Ransomware / RaaS | 75 |
| Kimsuky | APT / Nation-State | 74 |
| UNC6692 | Initial Access / Social Eng. | 72 |
| APT37 | APT / Nation-State | 71 |
| MuddyWater | APT / Nation-State | 70 |
| Black Basta | Ransomware / RaaS | 48 |

## Tactics & Tools on the Rise

In addition to actor profiles, SENTINEL tracks trending TTPs, malware, and exploits — the techniques and tools seeing a spike in threat-intel reporting, regardless of which actor (if any) is currently using them.

| Trend | Category | Status |
|---|---|---|
| ClickFix (Fake CAPTCHA / Verification Social Engineering) | Execution | Rising |
| Shai-Hulud npm Supply-Chain Worm | Supply Chain | Rising |
| Miasma (npm/PyPI Supply-Chain Worm) | Supply Chain | Rising |
| EDR Silencers / EDR Killer Tools | Defense Evasion | Rising |
| MS Teams Helpdesk Impersonation / Vishing | Initial Access | Rising |
| Lumma Stealer (LummaC2) | Credential Access | Rising |
| Rogue RMM Tool Abuse | Command and Control | Rising |
| BlueHammer (CVE-2026-33825) | Privilege Escalation | Rising |
| RedSun (CVE-2026-41091) | Privilege Escalation | Rising |

`data/trends.json` is the index (id, name, category, trend, mention_count_30d, sorted by mentions descending). Each entry has a full profile in `data/trends/<id>.json` with description, MITRE ATT&CK techniques, related actors/tools, notable examples, detection opportunities, sources, and 6-month mention history.

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

## Adding New Trend Entries

Create a new JSON file in `data/trends/` following the schema in any existing profile (`category` is one of: `initial_access`, `execution`, `persistence`, `defense_evasion`, `credential_access`, `command_and_control`, `supply_chain`, `privilege_escalation`). Add an entry (id, name, category, trend, mention_count_30d) to `data/trends.json`.

## Extending the Org Risk Profile

`data/exposure-mappings.json` is the knowledge base behind the Risk Profile tool (`docs/profile.html`). It maps verticals, cloud/business services, firewalls, endpoints, infrastructure, and special cases to MITRE ATT&CK techniques, keywords (matched against actor/trend data), curated mitigations (with `critical`/`high`/`medium` priority), and threat hunts. To add a new stack item, add an entry to the relevant category following the existing shape and add a corresponding checkbox in `docs/profile.html`.

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
