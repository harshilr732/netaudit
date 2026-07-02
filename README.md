# netaudit

A read-only network **asset discovery & vulnerability assessment** tool. It scans authorized networks, inventories every device and service, flags known vulnerabilities, and produces JSON / CSV reports — all without ever touching or destabilizing a target.

> **It detects and reports. It never exploits.** This is a vulnerability *assessment* and asset *audit* tool — not a penetration-testing or "full VAPT" tool.

---

## What it does

- **Asset discovery** — finds live hosts, open ports, and running services with version detection (via nmap)
- **OS detection** — best-effort OS fingerprinting (privileged scans)
- **Vulnerability flagging** — runs nmap NSE vulnerability scripts and, optionally, [Nuclei](https://github.com/projectdiscovery/nuclei) against discovered web endpoints
- **Findings with severity + confidence** — each finding carries a severity and a confidence level, so results can be triaged honestly instead of treated as absolute
- **Scan history** — every scan is stored in SQLite, so results can be compared over time
- **Reports** — JSON (full structured output), CSV (flat asset inventory), and a separate findings CSV

## Safety & scope

This tool is built around a single principle: **read-only**. Every scan option is detection-only.

- **No exploitation, brute-forcing, DoS, or stress testing.** When running nmap's NSE vulnerability scripts, it deliberately runs only the `vuln and safe` subset — excluding intrusive scripts (such as `http-slowloris`, which performs a denial-of-service). When running Nuclei, DoS and fuzzing templates are excluded (`-etags dos,fuzz`).
- **Authorized targets only.** Only scan networks you own or have **written** authorization and a defined scope to test.
- **Honest reporting.** Findings without a verified severity score are marked accordingly rather than assigned an invented rating. Empty findings on a patched host is a *pass*, not a failure.

## Architecture

```
Authorized targets
        │
        ▼
  Scanners (nmap NSE + Nuclei)      ← external detection engines
        │
        ▼
  Normalized schema (core/models)   ← one shape for everything: Host / Service / Finding
        │
        ▼
  Storage (SQLite)  ──►  Reporting (JSON / CSV / findings CSV / rich terminal)
```

Everything a scanner produces is normalized into the same `Host` / `Service` / `Finding` objects, so storage and reporting never need to understand individual tool formats. Adding a new engine later (e.g. OpenVAS) means writing one parser — nothing downstream changes.

```
netaudit/
├── __main__.py          # CLI entry point (python -m netaudit ...)
├── core/
│   ├── models.py        # normalized schema: Host, Service, Finding, Scan
│   └── storage.py       # SQLite persistence
├── scanners/
│   ├── nmap_scanner.py  # nmap via subprocess + XML parsing; NSE vuln findings
│   └── nuclei_scanner.py# Nuclei via subprocess + JSONL parsing
├── reporting/
│   ├── console.py       # rich terminal output
│   └── export.py        # JSON / CSV / findings-CSV export
├── collectors/          # (Phase 2 — credentialed WinRM/SSH collection)
└── enrichment/          # (Phase 3 — NVD CVE + endoflife.date)
```

## Requirements

- **Python 3.11+**
- **[nmap](https://nmap.org/download.html)** installed and on your PATH
- **[Nuclei](https://github.com/projectdiscovery/nuclei/releases)** *(optional)* — only needed for the `--nuclei` flag; the tool skips it cleanly if it's absent
- Python packages: `pip install -r requirements.txt` (just `rich` for now)

## Install

```bash
git clone https://github.com/harshilr732/netaudit.git
cd netaudit
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run from the folder that contains the `netaudit/` package.

```bash
# Discover hosts + services on your own machine (always safe — you own it)
python -m netaudit scan --targets 127.0.0.1

# A whole subnet, writing outputs where you want them
python -m netaudit scan --targets 192.168.1.0/24 --db data/netaudit.db --out reports

# Add nmap NSE vulnerability scripts (safe subset only)
python -m netaudit scan --targets 192.168.1.10 --vuln

# Add Nuclei against discovered web endpoints (needs the nuclei binary)
python -m netaudit scan --targets 192.168.1.10 --vuln --nuclei

# OS detection (requires Administrator on Windows / sudo on Linux)
sudo python -m netaudit scan --targets 192.168.1.0/24 --os
```

### Options

| Flag | Description |
|---|---|
| `--targets` | Comma-separated IPs / hostnames / CIDR you are **authorized** to scan (required) |
| `--ports` | Port spec, e.g. `1-1000` or `22,80,443` (default: nmap's top 1000) |
| `--vuln` | Run nmap NSE vulnerability scripts (safe subset only — no DoS/intrusive) |
| `--nuclei` | Run Nuclei against discovered web endpoints (DoS/fuzz templates excluded) |
| `--os` | Attempt OS detection (needs admin/root) |
| `--scripts` | Run nmap's default safe NSE scripts (`-sC`) |
| `--discovery-only` | Ping scan only (who's up), no port scan |
| `--db` | SQLite database path (default: `netaudit.db`) |
| `--out` | Output directory for JSON/CSV (default: `out`) |
| `--timeout` | Max seconds per scan (default: 900) |

## Output

- `reports/scan-<timestamp>.json` — full structured results (hosts, services, findings)
- `reports/scan-<timestamp>.csv` — flat asset inventory, one row per service
- `reports/findings-<timestamp>.csv` — one row per finding (only written when findings exist)
- `data/netaudit.db` — SQLite scan history

## Safe practice targets

- `127.0.0.1` — your own machine
- `scanme.nmap.org` — a host nmap maintains specifically for scan practice
- A cloud VM you spun up yourself

**Never** scan a network you don't own or lack written permission to test.

## Roadmap

- [x] **Phase 0** — project foundations, environment, structure
- [x] **Phase 1** — asset discovery + vulnerability scanning (nmap NSE + Nuclei), SQLite storage, JSON/CSV reporting
- [ ] **Phase 2** — credentialed collection (WinRM for Windows patch/AV/OS, SSH for Linux packages)
- [ ] **Phase 3** — enrichment (NVD CVE + CVSS, endoflife.date EOL flagging)
- [ ] **Phase 4** — client-ready PDF + Excel reports
- [ ] **Phase 5** — optional OpenVAS integration for deeper coverage
- [ ] **Phase 6** — scheduling & managed-service wrap
- [ ] **Phase 7** — optional Streamlit dashboard

## A note on third-party tool licenses

nmap has commercial-redistribution restrictions; Nuclei is permissive. Review the licenses of any bundled tools before packaging or distributing this tool commercially.
