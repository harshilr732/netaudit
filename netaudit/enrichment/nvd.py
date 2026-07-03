"""
enrichment/nvd.py — NVD (National Vulnerability Database) client for Phase 3.

WHAT THIS DOES
    Given a CVE ID (Path A) or a CPE (Path B), fetch the record from the NVD 2.0
    API and return a clean, normalized ``ParsedCve`` — CVSS score, severity,
    vector, description, references. Nothing here writes Findings or touches the
    schema; it is a pure "look up a CVE, give me back a tidy object" layer. The
    rules/enricher modules turn ParsedCve into Findings.

WHY IT LOOKS THE WAY IT DOES (the three design forces)
  1. RATE LIMITS. Without an API key the NVD allows 5 requests / 30s (~6s
     between calls); with a free key, 50 / 30s (~0.6s). Get a key:
     https://nvd.nist.gov/developers/request-an-api-key  — set it in the
     NVD_API_KEY env var. We throttle ourselves to be a polite citizen.
  2. CACHING IS MANDATORY, NOT OPTIONAL. Because of (1), a single subnet scan
     would otherwise spend an hour sleeping. CVE records change rarely, so we
     cache every successful lookup in SQLite and only hit the network on a miss.
  3. THE ENRICHMENT BACKLOG. Since 2024 the NVD has been slow to enrich newer
     CVEs, so a record may arrive with NO CVSS metrics at all. Every parse path
     therefore tolerates a completely absent score and degrades to UNKNOWN
     rather than crashing.

READ-ONLY: this only reads a public API. It never touches a scan target.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

# Severity is the only thing we borrow from the core schema — to translate NVD's
# severity strings into your enum. Everything else stays decoupled.
try:
    from ..core.models import Severity
except ImportError:  # allows running this file directly during development
    from enum import Enum

    class Severity(str, Enum):  # type: ignore
        INFO = "info"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
        UNKNOWN = "unknown"


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Sleep between requests. NVD's own recommendation, not just the hard limit.
THROTTLE_NO_KEY = 6.0
THROTTLE_WITH_KEY = 0.6

# CVEs get re-enriched over time (scores added), so don't cache forever.
DEFAULT_TTL_DAYS = 7


# ---------------------------------------------------------------------------
# Normalized return objects
# ---------------------------------------------------------------------------
@dataclass
class CvssScore:
    """The best single CVSS reading we could find for a CVE."""
    version: str          # "4.0" | "3.1" | "3.0" | "2.0"
    base_score: float     # 0.0 - 10.0
    base_severity: str    # NVD's string, uppercase: CRITICAL / HIGH / MEDIUM / LOW / NONE
    vector: str           # e.g. "CVSS:3.1/AV:N/AC:L/..."  (provenance for report review)


@dataclass
class ParsedCve:
    """A CVE record, flattened to only what enrichment needs."""
    cve_id: str
    description: str = ""
    cvss: Optional[CvssScore] = None       # None when NVD has no metrics yet (backlog)
    references: Optional[list[str]] = None

    def __post_init__(self) -> None:
        if self.references is None:
            self.references = []

    @property
    def severity(self) -> Severity:
        """Map to your schema's Severity, falling back to the numeric band."""
        if self.cvss is None:
            return Severity.UNKNOWN
        return severity_from_nvd(self.cvss.base_severity, self.cvss.base_score)

    @property
    def score(self) -> Optional[float]:
        return self.cvss.base_score if self.cvss else None


def severity_from_nvd(nvd_severity: str, score: Optional[float] = None) -> Severity:
    """
    NVD gives a severity string; we trust it when present. Backlog CVEs sometimes
    carry a score but no string, so we fall back to the standard CVSS band.
    """
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "NONE": Severity.INFO,
    }
    if nvd_severity and nvd_severity.upper() in mapping:
        return mapping[nvd_severity.upper()]
    if score is None:
        return Severity.UNKNOWN
    # CVSS v3/v4 bands (v2 has no CRITICAL, but this is a safe superset).
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Cache — one tiny SQLite table, keyed by CVE id
# ---------------------------------------------------------------------------
class NvdCache:
    """Persistent CVE cache so we hit the network as little as possible."""

    def __init__(self, path: str = "nvd_cache.sqlite", ttl_days: int = DEFAULT_TTL_DAYS):
        self.ttl_seconds = ttl_days * 86400
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS nvd_cache ("
            "  cve_id TEXT PRIMARY KEY,"
            "  payload TEXT NOT NULL,"
            "  fetched_at TEXT NOT NULL"
            ")"
        )
        self.conn.commit()

    def get(self, cve_id: str) -> Optional[ParsedCve]:
        row = self.conn.execute(
            "SELECT payload, fetched_at FROM nvd_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at)).total_seconds()
        if age > self.ttl_seconds:
            return None  # stale — let the caller re-fetch
        return _deserialize(json.loads(payload))

    def put(self, cve: ParsedCve) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO nvd_cache (cve_id, payload, fetched_at) VALUES (?, ?, ?)",
            (cve.cve_id, json.dumps(asdict(cve)), datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()


def _deserialize(d: dict) -> ParsedCve:
    cvss = CvssScore(**d["cvss"]) if d.get("cvss") else None
    return ParsedCve(
        cve_id=d["cve_id"],
        description=d.get("description", ""),
        cvss=cvss,
        references=d.get("references", []),
    )


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------
class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[NvdCache] = None,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache = cache if cache is not None else NvdCache()
        self.timeout = timeout
        self._throttle = THROTTLE_WITH_KEY if self.api_key else THROTTLE_NO_KEY
        self._last_request = 0.0
        self.session = requests.Session()

    # -- public API ---------------------------------------------------------
    def get_cve(self, cve_id: str) -> Optional[ParsedCve]:
        """Path A: look up one CVE by ID. Cache-first. Returns None if not found."""
        cve_id = cve_id.strip().upper()
        cached = self.cache.get(cve_id)
        if cached is not None:
            return cached
        data = self._request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", []) if data else []
        if not vulns:
            return None  # includes NVD's "HTTP 200 but empty body" case
        parsed = _parse_vulnerability(vulns[0])
        self.cache.put(parsed)
        return parsed

    def search_by_cpe(self, cpe: str, limit: int = 50) -> list[ParsedCve]:
        """
        Path B: find CVEs affecting a CPE. Opt-in, noisy, TENTATIVE by nature —
        the caller is responsible for capping confidence. Kept here so the
        capability exists; wire it up only when you decide to enable Path B.
        """
        data = self._request({"virtualMatchString": cpe, "resultsPerPage": limit})
        out: list[ParsedCve] = []
        for v in (data.get("vulnerabilities", []) if data else []):
            parsed = _parse_vulnerability(v)
            self.cache.put(parsed)
            out.append(parsed)
        return out

    # -- internals ----------------------------------------------------------
    def _request(self, params: dict) -> Optional[dict]:
        self._respect_throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(3):
            try:
                resp = self.session.get(
                    NVD_BASE_URL, params=params, headers=headers, timeout=self.timeout
                )
            except requests.RequestException:
                time.sleep(self._throttle * (attempt + 1))
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    return None
            if resp.status_code in (403, 429, 503):
                # rate-limited or transient — back off and retry
                time.sleep(self._throttle * (attempt + 2))
                continue
            resp.raise_for_status()
        return None

    def _respect_throttle(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self._throttle:
            time.sleep(self._throttle - elapsed)
        self._last_request = time.time()


# ---------------------------------------------------------------------------
# Parsing — turn NVD's nested JSON into a ParsedCve
# ---------------------------------------------------------------------------
def _parse_vulnerability(vuln: dict) -> ParsedCve:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    references = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return ParsedCve(
        cve_id=cve_id,
        description=description,
        cvss=_pick_best_cvss(cve.get("metrics", {})),
        references=references,
    )


def _pick_best_cvss(metrics: dict) -> Optional[CvssScore]:
    """
    A CVE can carry v2, v3.0, v3.1 and v4.0 metrics at once. Prefer newest.
    Note the v2 quirk: baseSeverity lives OUTSIDE cvssData (unlike v3/v4).
    """
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if not entries:
            continue
        # Prefer the Primary source when more than one exists.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        base_score = data.get("baseScore")
        if base_score is None:
            continue
        # v3/v4 put severity in cvssData; v2 puts it on the entry itself.
        base_severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        return CvssScore(
            version=version,
            base_score=float(base_score),
            base_severity=str(base_severity),
            vector=data.get("vectorString", ""),
        )
    return None


# ---------------------------------------------------------------------------
# Demo: python -m netaudit.enrichment.nvd CVE-2021-44228
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    client = NvdClient()
    print(f"Looking up {cve_id} "
          f"({'with' if client.api_key else 'NO'} API key — "
          f"throttling {client._throttle}s)...")
    result = client.get_cve(cve_id)
    if result is None:
        print("Not found.")
    else:
        print(f"  {result.cve_id}")
        print(f"  severity : {result.severity.value}")
        print(f"  cvss     : {result.score} "
              f"({result.cvss.version if result.cvss else 'none'})")
        print(f"  vector   : {result.cvss.vector if result.cvss else '-'}")
        print(f"  desc     : {result.description[:120]}...")
