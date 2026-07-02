# NetAudit — Automated Vulnerability Assessment & Asset Auditing Tool

An internal, read-only tool that audits a network's security posture and produces
reports: asset inventory, end-of-life systems, missing patches, antivirus status,
exposed services, and known vulnerabilities.

## Scope & safety
- Read-only: it detects and reports. It does not exploit, brute-force, or attack.
- This is a vulnerability assessment & asset audit tool — not a penetration test.
- Only run against systems you own or have written authorization to scan.
- Never commit client scan data to version control.

## Status
Phase 0 — project setup (in development).

## Setup
1. Create and activate a virtual environment.
2. `pip install -r requirements.txt`
3. `python main.py`