"""
core/storage.py — SQLite persistence.

Why SQLite: it's a single file, zero setup, ships with Python, and is plenty for
your scale. The guide upgrades to PostgreSQL later; because all DB access goes
through this one class, that swap touches only this file.

Data model (one row per scan run keeps full history so you can show trends later):

    scans      one row per run of the tool
      └─ hosts        one row per machine seen in that scan   (scan_id FK)
           ├─ services   one row per open port on that host   (host_id FK)
           └─ findings   one row per security observation      (host_id FK)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from netaudit.core.models import Finding, Host, Scan, Service, Severity, Confidence

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    targets      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    nmap_version TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    state       TEXT,
    mac         TEXT,
    vendor      TEXT,
    os_name     TEXT,
    os_accuracy INTEGER,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    protocol   TEXT,
    state      TEXT,
    name       TEXT,
    product    TEXT,
    version    TEXT,
    extra_info TEXT,
    cpe        TEXT   -- JSON-encoded list
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source      TEXT,
    title       TEXT,
    severity    TEXT,
    confidence  TEXT,
    port        INTEGER,
    cve         TEXT,
    cvss        REAL,
    description TEXT,
    references_ TEXT  -- JSON-encoded list ('references' is not reserved but we avoid confusion)
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
"""


class Database:
    def __init__(self, path: str | Path = "netaudit.db"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def save_scan(self, scan: Scan) -> int:
        """Persist a whole Scan (with its hosts, services, findings). Returns scan_id."""
        cur = self.conn.execute(
            "INSERT INTO scans (targets, started_at, finished_at, nmap_version) VALUES (?, ?, ?, ?)",
            (scan.targets, scan.started_at, scan.finished_at, scan.nmap_version),
        )
        scan_id = cur.lastrowid
        for host in scan.hosts:
            self._save_host(scan_id, host)
        self.conn.commit()
        return scan_id

    def _save_host(self, scan_id: int, host: Host) -> int:
        cur = self.conn.execute(
            """INSERT INTO hosts (scan_id, ip, hostname, state, mac, vendor, os_name, os_accuracy, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, host.ip, host.hostname, host.state, host.mac, host.vendor,
             host.os_name, host.os_accuracy, host.last_seen),
        )
        host_id = cur.lastrowid
        for svc in host.services:
            self.conn.execute(
                """INSERT INTO services (host_id, port, protocol, state, name, product, version, extra_info, cpe)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (host_id, svc.port, svc.protocol, svc.state, svc.name, svc.product,
                 svc.version, svc.extra_info, json.dumps(svc.cpe)),
            )
        for f in host.findings:
            self.conn.execute(
                """INSERT INTO findings (host_id, source, title, severity, confidence, port, cve, cvss, description, references_)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (host_id, f.source, f.title, f.severity.value, f.confidence.value, f.port,
                 f.cve, f.cvss, f.description, json.dumps(f.references)),
            )
        return host_id

    def close(self) -> None:
        self.conn.close()
