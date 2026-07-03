"""
enrichment/eol.py — End-of-Life (EOL) checker for Phase 3.

WHAT THIS DOES
    Takes the *confirmed* OS from your Phase 2 credentialed collection
    (OSInfo: family / product / version / build) and asks endoflife.date whether
    that operating system is still supported or has reached end-of-life. An EOL
    OS is a real, serious finding: the vendor has stopped shipping security
    patches, so vulnerabilities pile up with no fix.

WHY IT NEEDS PHASE 2
    An nmap OS *guess* ("probably Windows 10") isn't precise enough — Windows 10
    22H2 and 21H2 have DIFFERENT end-of-life dates. Only the credentialed build
    number (e.g. 19045) tells them apart. That's why EOL judgement lives here in
    Phase 3, keyed off the build your credentialed collector reads.

DATA SOURCE
    endoflife.date, free public API: https://endoflife.date/api/{product}.json
    Returns a list of "release cycles", each with an `eol` field that is either a
    date ("2025-10-14") or the boolean false (still supported).

READ-ONLY: reads a public API, touches nothing on the target.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Optional

import requests

try:
    from ..core.models import OSInfo, Finding, Severity, Confidence
except ImportError:  # allow running this file directly while developing
    from dataclasses import dataclass as _dc
    from enum import Enum

    class Severity(str, Enum):  # type: ignore
        INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"
        CRITICAL = "critical"; UNKNOWN = "unknown"

    class Confidence(str, Enum):  # type: ignore
        CONFIRMED = "confirmed"; FIRM = "firm"; TENTATIVE = "tentative"

    @_dc
    class OSInfo:  # type: ignore
        family: str; product: str = ""; version: str = ""; build: str = ""; architecture: str = ""

    @_dc
    class Finding:  # type: ignore
        source: str; title: str; severity: Severity = Severity.UNKNOWN
        confidence: Confidence = Confidence.TENTATIVE; port: Optional[int] = None
        cve: str = ""; cvss: Optional[float] = None; description: str = ""
        references: Optional[list] = None


EOL_BASE_URL = "https://endoflife.date/api"
APPROACHING_DAYS = 180   # flag "support ending soon" within this window

# --- Windows client: build number -> feature-update shorthand --------------
# Extend as new Windows releases ship. Build number is the reliable key.
WIN_BUILD_TO_FEATURE = {
    "19044": "21h2", "19045": "22h2",                       # Windows 10
    "22000": "21h2", "22621": "22h2", "22631": "23h2",      # Windows 11
    "26100": "24h2",                                        # Windows 11
}

# --- Windows Server: build number -> release year (fallback if name lacks it)
WIN_SERVER_BUILD_TO_YEAR = {
    "14393": "2016", "17763": "2019", "20348": "2022", "26100": "2025",
}

# --- Linux: product name (lowercased) -> endoflife.date slug ----------------
LINUX_SLUGS = {
    "ubuntu": "ubuntu", "debian": "debian", "fedora": "fedora",
    "centos": "centos", "rhel": "rhel", "red hat": "rhel",
    "rocky": "rocky-linux", "alma": "almalinux", "alpine": "alpine",
    "amazon": "amazon-linux", "opensuse": "opensuse", "suse": "sles",
}


@dataclass
class EolResult:
    matched: bool                       # did we find this OS in endoflife.date?
    product_slug: str = ""              # e.g. "windows", "ubuntu"
    cycle: str = ""                     # the matched release cycle, e.g. "22h2"
    eol_date: Optional[str] = None      # "YYYY-MM-DD" or None
    is_eol: Optional[bool] = None       # True=past EOL, False=supported, None=unknown
    days_until_eol: Optional[int] = None
    message: str = ""


# ---------------------------------------------------------------------------
# Cache (endoflife.date is generous, but caching keeps scans fast and polite)
# ---------------------------------------------------------------------------
class EolCache:
    def __init__(self, path: str = "eol_cache.sqlite", ttl_hours: int = 24):
        self.ttl_seconds = ttl_hours * 3600
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS eol_cache ("
            " slug TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at TEXT NOT NULL)"
        )
        self.conn.commit()

    def get(self, slug: str) -> Optional[list]:
        row = self.conn.execute(
            "SELECT payload, fetched_at FROM eol_cache WHERE slug = ?", (slug,)
        ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at)).total_seconds()
        if age > self.ttl_seconds:
            return None
        return json.loads(payload)

    def put(self, slug: str, cycles: list) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO eol_cache (slug, payload, fetched_at) VALUES (?, ?, ?)",
            (slug, json.dumps(cycles), datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------
class EolClient:
    def __init__(self, cache: Optional[EolCache] = None, timeout: float = 20.0):
        self.cache = cache if cache is not None else EolCache()
        self.timeout = timeout
        self.session = requests.Session()

    def _get_product(self, slug: str) -> Optional[list]:
        cached = self.cache.get(slug)
        if cached is not None:
            return cached
        try:
            resp = self.session.get(f"{EOL_BASE_URL}/{slug}.json", timeout=self.timeout)
        except requests.RequestException:
            return None
        if resp.status_code != 200:
            return None          # unknown product / network issue
        try:
            cycles = resp.json()
        except ValueError:
            return None
        self.cache.put(slug, cycles)
        return cycles

    def check_os(self, os_info: OSInfo) -> EolResult:
        """Main entry point: OSInfo -> EolResult."""
        slug, candidate_cycles = _resolve(os_info)
        if not slug:
            return EolResult(matched=False, message=f"No EOL mapping for '{os_info.product}'")

        cycles = self._get_product(slug)
        if not cycles:
            return EolResult(matched=False, product_slug=slug,
                             message=f"Could not fetch EOL data for '{slug}'")

        # Try each candidate cycle string against the product's cycle list.
        available = {str(c.get("cycle", "")).lower(): c for c in cycles}
        for cand in candidate_cycles:
            match = available.get(cand.lower())
            if match:
                return _evaluate_cycle(slug, cand, match)

        return EolResult(matched=False, product_slug=slug,
                         message=f"OS '{os_info.product}' build '{os_info.build}' "
                                 f"not matched to a {slug} cycle")


# ---------------------------------------------------------------------------
# OSInfo -> (product slug, candidate release-cycle strings)
# ---------------------------------------------------------------------------
def _resolve(os_info: OSInfo) -> tuple[str, list[str]]:
    family = (os_info.family or "").lower()
    product = (os_info.product or "").lower()
    build = _extract_build(os_info)

    if family == "windows":
        if "server" in product:
            year = _first_match(r"(2008|2012|2016|2019|2022|2025)", product) \
                   or WIN_SERVER_BUILD_TO_YEAR.get(build, "")
            if not year:
                return "windows-server", []
            has_r2 = "r2" in product
            cands = [f"{year}-r2", year] if has_r2 else [year]
            return "windows-server", cands
        # Windows client (10 / 11)
        win = "11" if "11" in product else "10"
        feature = WIN_BUILD_TO_FEATURE.get(build, "")
        if not feature:
            return "windows", []
        edition = "-e" if any(k in product for k in ("enterprise", "education", "iot")) else "-w"
        # Win10 recent cycles have no suffix; Win11 uses -e/-w. Try both to be safe.
        return "windows", [
            f"{win}-{feature}{edition}",
            f"{win}-{feature}",
            f"{win}-{feature}{'-w' if edition == '-e' else '-e'}",
        ]

    if family == "linux":
        slug = ""
        for key, val in LINUX_SLUGS.items():
            if key in product:
                slug = val
                break
        if not slug:
            return "", []
        ver = os_info.version.strip()
        major = ver.split(".")[0] if ver else ""
        cands = [c for c in (ver, major) if c]   # try "20.04" then "20"
        return slug, cands

    return "", []


def _evaluate_cycle(slug: str, cycle: str, data: dict) -> EolResult:
    eol = data.get("eol")
    # eol can be: a date string, False (supported), or True (EOL, no date).
    if eol is False:
        return EolResult(True, slug, cycle, None, is_eol=False,
                         message="Supported (no EOL date announced)")
    if eol is True:
        return EolResult(True, slug, cycle, None, is_eol=True,
                         message="End of life")
    # eol is a date string
    try:
        eol_date = datetime.strptime(str(eol), "%Y-%m-%d").date()
    except ValueError:
        return EolResult(True, slug, cycle, str(eol), is_eol=None,
                         message=f"Unparseable EOL date: {eol}")
    today = date.today()
    days = (eol_date - today).days
    return EolResult(
        matched=True, product_slug=slug, cycle=cycle, eol_date=str(eol_date),
        is_eol=days <= 0, days_until_eol=days,
        message=("End of life since " + str(eol_date)) if days <= 0
                else f"Supported until {eol_date} ({days} days)",
    )


# ---------------------------------------------------------------------------
# EolResult -> Finding (confidence decided by the caller: CONFIRMED when the OS
# came from credentialed collection, TENTATIVE when only from an nmap guess)
# ---------------------------------------------------------------------------
def eol_finding(result: EolResult, confidence: Confidence) -> Optional[Finding]:
    if not result.matched or result.is_eol is None:
        return None

    if result.is_eol:
        return Finding(
            source="eol",
            title=f"End-of-life operating system ({result.product_slug} {result.cycle})",
            severity=Severity.HIGH,
            confidence=confidence,
            description=(f"{result.message}. No further security updates are "
                         f"released for this OS; upgrade to a supported version."),
            references=["https://endoflife.date/" + result.product_slug],
        )

    if result.days_until_eol is not None and 0 < result.days_until_eol <= APPROACHING_DAYS:
        return Finding(
            source="eol",
            title=f"OS approaching end-of-life ({result.product_slug} {result.cycle})",
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=f"{result.message}. Plan an upgrade before support ends.",
            references=["https://endoflife.date/" + result.product_slug],
        )
    return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _extract_build(os_info: OSInfo) -> str:
    """Pull the 5-digit Windows build from build or version ('10.0.19045' -> '19045')."""
    for src in (os_info.build, os_info.version):
        if not src:
            continue
        m = re.search(r"(\d{5})", src)
        if m:
            return m.group(1)
    return ""


def _first_match(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Demo: python -m netaudit.enrichment.eol
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    client = EolClient()
    samples = [
        OSInfo(family="windows", product="Windows Server 2016 Standard", version="10.0.14393", build="14393"),
        OSInfo(family="windows", product="Windows 10 Pro", version="10.0.19045", build="19045"),
        OSInfo(family="linux", product="Ubuntu", version="20.04"),
        OSInfo(family="linux", product="Ubuntu", version="18.04"),
    ]
    for os_info in samples:
        r = client.check_os(os_info)
        verdict = "EOL" if r.is_eol else ("supported" if r.is_eol is False else "unknown")
        print(f"{os_info.product:<32} -> [{verdict:^9}] {r.message}")
        f = eol_finding(r, Confidence.CONFIRMED)
        if f:
            print(f"    finding: [{f.severity.value}] {f.title}")
