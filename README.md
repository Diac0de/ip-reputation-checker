# IP Reputation Checker — SOC Tier-1 Automation Tool

A command-line tool that automates IP threat enrichment for SOC analysts.
Given an IP address, it queries **AbuseIPDB** and **VirusTotal** simultaneously,
applies a verdict scoring engine, and outputs a structured threat report in seconds.

---

## Why This Exists

In a SOC, Tier-1 analysts manually look up IPs dozens of times per shift:
open AbuseIPDB in one tab, VirusTotal in another, copy the scores, write a note.

This tool replaces that entire workflow with one command.

```
python main.py 185.220.101.1
```

---

## Demo Output

```
════════════════════════════════════════════════════════════
  IP REPUTATION REPORT
────────────────────────────────────────────────────────────
  Target IP   : 185.220.101.1
  Scan Time   : 2024-03-15 10:42:11 UTC
════════════════════════════════════════════════════════════

  [ AbuseIPDB ]
  ────────────────────────────────────────
  Confidence Score : 97/100
  Total Reports    : 842
  Country          : DE
  ISP              : Tor Exit Node ISP
  Usage Type       : Data Center/Web Hosting/Transit
  Whitelisted      : No

  [ VirusTotal ]
  ────────────────────────────────────────
  Malicious        : 8 / 76 engines
  Suspicious       : 2 / 76 engines
  Harmless         : 52
  Last Analysis    : 2024-03-14

  [ FINAL VERDICT ]
  ────────────────────────────────────────
  🔴 MALICIOUS

  Reason:
    • [AbuseIPDB] Abuse confidence score is 97/100 (>= 50). Reported 842 times.
    • [VirusTotal] 8/76 engines flagged as MALICIOUS (threshold: 3).

════════════════════════════════════════════════════════════
```

---

## Setup

### 1. Get free API keys

| Service | Free Tier | Link |
|---|---|---|
| AbuseIPDB | 1,000 req/day | https://www.abuseipdb.com/api |
| VirusTotal | 500 req/day | https://www.virustotal.com/gui/join-us |

### 2. Install & configure

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Open .env and paste your keys
```

### 3. Run

```bash
python main.py 185.220.101.1
```

---

## Usage

```bash
# Full check (both sources)
python main.py <IP>

# Skip one source
python main.py <IP> --no-virustotal
python main.py <IP> --no-abuseipdb

# Help
python main.py --help
```

---

## How It Fits in a SOC Workflow

```
SIEM Alert → Extract IP → python main.py <IP> → Read Verdict → Escalate or Close
```

This tool handles the enrichment step — the part that currently takes
2-5 minutes of manual tab-switching per alert.

> **Note:** A CLEAN verdict does not mean safe. New malicious IPs have no history.
> Always combine with log context and SIEM correlation.

---

## Architecture

The tool follows a strict layered pipeline. Each module has one job:

```
Input → Validate → [AbuseIPDB] → [VirusTotal] → Verdict Engine → Report
```

| Module | Responsibility |
|---|---|
| `models.py` | Typed dataclasses + enums. No logic, only data structure |
| `validator.py` | Sanitize IP before any network call. Blocks private/reserved ranges |
| `api_clients.py` | Query APIs. Fail gracefully — never crash on network errors |
| `verdict_engine.py` | Score results. Highest-severity-wins across all sources |
| `reporter.py` | Color-coded terminal output |
| `main.py` | Orchestrate the pipeline. Parse CLI args |

**Design principles:** Separation of Concerns · Single Responsibility · Fail Gracefully · Environment-based secrets

---

## Project Structure

```
ip_reputation_checker/
├── main.py                  # Entry point & pipeline orchestration
├── requirements.txt
├── .env.example             # API key template (never commit .env)
└── src/
    ├── models.py            # Data structures (dataclasses + enums)
    ├── validator.py         # Input validation
    ├── api_clients.py       # AbuseIPDB + VirusTotal API clients
    ├── verdict_engine.py    # Threat scoring & verdict logic
    └── reporter.py          # Terminal output / presentation
```

---

## Roadmap

- [ ] Bulk IP input from `.txt` file
- [ ] JSON / CSV export for SIEM ingestion
- [ ] GreyNoise integration (scanner/noise classification)
- [ ] Async parallel API queries
- [ ] Domain and file hash support

---

## Security Note

API keys are loaded from a `.env` file and never hardcoded.
The `.gitignore` excludes `.env` from version control.
