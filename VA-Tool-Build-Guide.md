# Build Guide — Automated Vulnerability Assessment & Asset Auditing Tool

> Your complete blueprint. Read this, then start a new chat per phase and we build it piece by piece. You can upload this file into any new chat to give me instant context.

---

## 1. What we're building (and what we're deliberately NOT)

**A tool that automatically audits a network and reports its security posture** — delivered as a managed service alongside your company's network offering.

**In scope — it DETECTS and REPORTS, never exploits:**
- Asset discovery & inventory (live hosts, OS, roles, open ports/services)
- End-of-life / legacy-OS flagging with upgrade recommendations
- Patch status and outdated software (credentialed)
- Antivirus presence and status (credentialed)
- Exposed / insecure services (Telnet, FTP, plain HTTP, SMBv1)
- Known-CVE mapping with severity + confidence levels
- TLS certificate expiry and weak-config checks
- PDF + Excel reports

**Explicitly OUT of scope (write this into the tool's own docs):**
- No exploitation, brute-forcing, DoS, or stress testing
- Nothing that modifies or destabilizes a target
- It is a **vulnerability assessment & asset audit tool**, never marketed as "penetration testing" or "full VAPT"

**The one safety principle that covers you:** read-only. A tool that only reads and reports is far less likely to break anything, and the scope language protects the company legally.

---

## 2. Architecture (the three-part backend + reporting)

```
Authorized targets
        │
   ┌────┴─────────────────────┐
   ▼                          ▼
Network + vuln scan     Credentialed scan
(Nmap + NSE scripts,    (WinRM/SSH: real OS
 Nuclei: ports,          build, patches, AV)
 versions, known CVEs)
   └────────────┬────────────┘
                ▼
     Orchestrator (your Python logic)
       normalize → one data schema
                ▼
          Enrichment
     (CVE/NVD + EOL data + rules)
                ▼
        Store (SQLite) → Report (PDF + Excel)

  [OpenVAS — optional future engine, plugs in here on a Linux box]
```

The backend has **three parts**, and dropping any one weakens it:
1. **External scanners** — **Nmap (with NSE vuln scripts) + Nuclei** as the primary engine, both lightweight and Windows-friendly. OpenVAS is an *optional later upgrade* that plugs into the same pipeline for deeper coverage (see Phase 5).
2. **Credentialed collectors** — the accuracy layer. Logs into hosts for the real patch/AV/OS data. *This is the part that makes the tool trustworthy, and it's identical no matter which scanner you use — don't skip it.*
3. **Your own logic** — normalizes everything into one schema, enriches with CVE/EOL data, applies rules (e.g. "OS is Server 2016 → flag EOL"), and drives reporting.

**On engine choice:** Nmap NSE + Nuclei give solid, honest coverage and run anywhere. OpenVAS has a larger vulnerability feed (it'll find some things the lighter engines miss) but it's a heavy always-on Linux service — so it's a deliberate *later* upgrade, not a requirement. Because the orchestrator just collects scanner output, adding OpenVAS later widens the net without rewriting anything.

---

## 3. Tech stack (what, and why)

| Layer | Tool / Library | Why |
|---|---|---|
| Language | **Python 3.11+** | Every security library lives here; it's what you're learning |
| Network scan | **Nmap** + `python-nmap` (or `subprocess`) | Industry standard for host/port/service/OS discovery |
| Vuln engine (primary) | **Nuclei** via `subprocess` + **Nmap NSE** vuln scripts | Fast, lightweight, Windows-friendly; large community CVE/misconfig coverage |
| Web-server checks | **Nikto** via `subprocess` *(optional)* | Specialist scanner for web servers only — narrow but useful add-on |
| Vuln engine (later) | **OpenVAS / Greenbone (GVM)** + `python-gvm` | Deeper vuln feed; heavy always-on **Linux** service, added as a future upgrade |
| Windows collector | `pywinrm` (or `impacket`) | Reads AV status (`root\SecurityCenter2`), patches, OS build over WinRM/WMI |
| Linux collector | `paramiko` (SSH) | Reads installed packages/versions |
| CVE enrichment | **NVD API** via `requests` (or `nvdlib`) | Official CVE data + CVSS severity scores |
| EOL data | **endoflife.date** API | Live end-of-life dates for OS/software — don't hardcode them |
| Storage | **SQLite** (`sqlite3` stdlib) → PostgreSQL later | Zero-config, perfect for your scale and hardware |
| Reports | `openpyxl` (Excel) + `reportlab` or Jinja2→WeasyPrint (PDF) | Native Python report generation |
| Scheduling | `cron` / Task Scheduler → APScheduler later | Runs the managed-service scans automatically |
| API (later) | **FastAPI** | Modern, easy, auto-docs; serves data to a frontend |
| Dashboard (last) | **Streamlit** | Build a data dashboard in pure Python — no frontend skills needed |
| Version control | **Git + GitHub** | Also becomes your portfolio (ties to your career goals) |
| Editor | **VS Code** | Light enough for your machine |

**On the frontend:** don't build a full React web app early — it's a separate project that will balloon the scope before your engine even works. Reports are your first "output." When you want a UI, **Streamlit** lets you build a real dashboard in Python. React only if the company later productizes it.

---

## 4. Where it runs (dev machine vs production)

Two different machines, and keeping them separate clears up most confusion:

**Your laptop = the development machine.** Where you write and test the code. With the primary engine (Nmap NSE + Nuclei), the *entire* tool runs here — Python, Nmap, Nuclei, credentialed collectors, enrichment, SQLite, reporting, even a Streamlit dashboard. All lightweight, all fine on 4GB. No server needed to build the whole thing.

**A company server/VM = the production machine.** Where the finished tool actually runs for clients (the weekly scheduled scans). It should never depend on your personal laptop being switched on. With the light engine, this can be a modest server — and a Windows VM works, since Nmap and Nuclei run on Windows.

**About OpenVAS specifically (the later upgrade):** OpenVAS runs on **Linux only** — there's no proper native Windows version. So if/when you add it, it needs either a Linux VM, or Docker/WSL2 on a capable Windows box (8GB+ RAM). It's a separate always-on service your tool talks to over the network. Because it's optional, none of this blocks your build — you develop and ship v1 with the light engine first.

**Safe test targets while learning (no big VMs needed):**
- Your own laptop (`localhost`) and phone on your home network — you own them, so scanning is fine
- One small cloud VM you spin up as a practice target
- Later, a single intentionally-vulnerable target if RAM allows

**Never** point any scan at a network you don't own or lack written permission to test.

---

## 5. The phased build roadmap

Each phase produces a **working, demoable increment** — so you can show your manager real progress every step, not just at the end.

### Phase 0 — Foundations & setup
- **Build:** project repo, Python virtual environment, folder structure (`collectors/`, `scanners/`, `enrichment/`, `reporting/`, `core/`), Git initialized.
- **Learn first:** Python basics solid (functions, classes/dataclasses, file I/O, error handling), Git/GitHub basics, Nmap fundamentals, basic networking (ports/services — you've started this).

### Phase 1 — Asset discovery + vuln scanning MVP
- **Build:** wrap Nmap to find live hosts + open ports + services, run Nmap NSE vuln scripts and Nuclei against discovered services, parse all results, store in SQLite, output a simple CSV/JSON inventory with findings.
- **Learn:** `python-nmap`, Nmap NSE basics, running Nuclei from `subprocess` and parsing its JSON output, `argparse`, `dataclasses`, `sqlite3`.
- **Milestone:** "It scans a network, lists every device, and flags known vulnerabilities." Already demoable.

### Phase 2 — Credentialed collection (the accuracy layer)
- **Build:** log into Windows hosts (`pywinrm`) to read OS build, patch status, AV status; log into Linux hosts (`paramiko`) to read packages/versions. Merge with Phase 1 data.
- **Learn:** WinRM/WMI, the `SecurityCenter2` namespace, SSH, service accounts, and (conceptually) how one AD service account + Group Policy covers hundreds of hosts.
- **Milestone:** accurate, real per-host data — no more guessing.

### Phase 3 — Enrichment (CVE + EOL)
- **Build:** query the NVD API to attach CVE/CVSS severity to findings; query endoflife.date to flag EOL operating systems; apply your rule logic (EOL flags, disabled-AV flags, insecure-protocol flags) with confidence levels.
- **Learn:** REST APIs, `requests`, CVE/CVSS concepts, handling false positives via confidence + cross-checking your two data sources.
- **Milestone:** findings now have severity and plain-English meaning.

### Phase 4 — Reporting
- **Build:** generate a PDF (exec summary + findings + remediation) and an Excel workbook (full asset inventory + findings sheet).
- **Learn:** `openpyxl`, and Jinja2→WeasyPrint or `reportlab`.
- **Milestone:** a client-ready report comes out the other end. This is the "product."

### Phase 5 — OpenVAS integration (optional future upgrade, on Linux)
- **When:** only if the company wants deeper vulnerability coverage than Nmap NSE + Nuclei provide. v1 is a complete, deliverable tool without this.
- **Build:** stand up GVM on a Linux box (or Docker/WSL2 on a capable Windows VM), control it via `python-gvm`, feed its findings into the same pipeline and dedupe against your existing checks.
- **Learn:** GVM setup/administration, `python-gvm`, basic Linux deployment.
- **Milestone:** widened vuln coverage, without changing anything else in the tool.

### Phase 6 — Scheduling & managed-service wrap
- **Build:** scheduled runs (cron/APScheduler), multi-client config, proper logging, and email/alert on new high findings.
- **Learn:** scheduling, logging, config management, multi-tenant data separation.
- **Milestone:** it's now a *service*, not a script.

### Phase 7 — Dashboard (optional, last)
- **Build:** a Streamlit dashboard showing inventory, findings, and trends per client. (FastAPI + web UI only if productizing.)
- **Learn:** Streamlit (or FastAPI).

---

## 6. How we'll work together in the new chats

- **One phase per chat.** Don't try to build the whole thing in one conversation — it gets unwieldy and you learn less. Finish a phase, then start fresh for the next.
- **Start each chat with context.** Open with: *"I'm building the VA tool from my build guide (attached). We're on Phase X. Here's what I've done / where I'm stuck."* Uploading this file makes that instant.
- **What I'll do each phase:** explain every concept before we use it (you're learning, not just copying), design the module with you, write and review the code, explain *why* each piece works, help you debug errors, and suggest how to test it safely.
- **What you bring:** the phase, your current code/errors, and questions. Don't worry about not knowing something — that's the point.
- **Tooling tip:** for the actual coding across many files and sessions, Claude Code (in the desktop app) is far better suited than this chat window — it can read and edit your project files directly. Worth setting up before Phase 1.

---

## 7. Pre-flight checklist (do before Phase 1)

- [ ] Python 3.11+ installed; comfortable with the basics
- [ ] VS Code installed
- [ ] Git installed + GitHub account created
- [ ] Nmap installed
- [ ] Nuclei installed (and templates updated)
- [ ] A GitHub repo created for the project
- [ ] A safe test target identified (start with your own machine)
- [ ] **Manager sign-off on the project**, and a shared understanding that any client scan needs written authorization and defined scope first
- [ ] This guide saved where you'll find it

---

## 8. Non-negotiable reminders

- **Read-only, detect-and-report only.** No exploitation, ever.
- **Only scan what you own or are authorized in writing to scan.**
- **Credentialed scanning = accuracy.** It's the method, not any single tool's brand.
- **Findings get reviewed before reaching a client** — early on, someone senior reviews *yours*. Ask who signs off.
- **Language discipline:** "vulnerability assessment & asset audit," never "pentest" or "full VAPT."
- **Scope v1 honestly.** Nmap NSE + Nuclei give solid, real coverage — but narrower than OpenVAS. Describe reports as what the tool actually does ("assessment via Nuclei and Nmap plus credentialed patch/AV/EOL auditing"); never imply exhaustive enterprise scanning. Over-claiming is the real risk, not the lighter engine.
- **Coverage-vs-cost is the manager's call.** Surface the OpenVAS upgrade as a deliberate option; don't decide it silently.
- **Check third-party tool licenses** before the company ever packages/sells the tool (Nmap has commercial-redistribution restrictions; Nuclei and OpenVAS are permissive). Raise it; don't decide it alone.

---

When you're ready, open a new chat, attach this file, and say: **"Let's start Phase 0."** We'll set up the project structure and your environment first, then move to real scanning in Phase 1.
