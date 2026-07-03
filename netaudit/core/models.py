"""
core/models.py — the normalized data schema.

Everything the tool produces gets converted into these objects, no matter which
scanner produced it. This is the single most important design decision in the
whole project: if the Nmap scanner, the Nuclei scanner, and (later) OpenVAS all
speak *different* output formats but get normalized into the SAME Host / Service
/ Finding shapes here, then storage, enrichment, and reporting only ever have to
understand one shape. Add a new scanner later? You only write a new parser that
outputs these objects — nothing downstream changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


def _now_iso() -> str:
    """Timezone-aware UTC timestamp. Always store times in UTC; format for humans later."""
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    """Ordered severity levels. Inheriting from str makes these JSON-friendly."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """
    How sure we are a finding is real. This is what lets us avoid crying wolf.
    A version-string guess is FIRM at best; something confirmed by a credentialed
    login (Phase 2) is CONFIRMED. Reports should show this so a human can triage.
    """
    CONFIRMED = "confirmed"   # verified on the host itself (e.g. credentialed check)
    FIRM = "firm"             # strong signal (e.g. Nuclei template matched)
    TENTATIVE = "tentative"   # inferred from a banner/version only — could be a false positive


@dataclass
class Service:
    """One open port/service on a host."""
    port: int
    protocol: str = "tcp"            # tcp / udp
    state: str = "open"             # open / filtered / closed
    name: str = ""                  # nmap's service name, e.g. "http", "ssh"
    product: str = ""               # e.g. "Apache httpd"
    version: str = ""               # e.g. "2.4.29"
    extra_info: str = ""            # e.g. "(Ubuntu)"
    cpe: list[str] = field(default_factory=list)  # machine-readable product IDs, gold for CVE lookup later

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """
    A single security-relevant observation. Phase 1 fills these from Nmap NSE /
    Nuclei; Phase 3 enriches them with CVE + CVSS from NVD. Defined now so the
    schema and DB are ready and nothing has to be rewritten later.
    """
    source: str                                   # "nmap-nse", "nuclei", "rule", "openvas"...
    title: str
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.TENTATIVE
    port: int | None = None
    cve: str = ""                                 # e.g. "CVE-2021-44228" (filled in Phase 3)
    cvss: float | None = None                     # numeric CVSS score (Phase 3)
    description: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Host:
    """One machine discovered on the network, with its services and findings."""
    ip: str
    hostname: str | None = None
    state: str = "up"
    mac: str | None = None
    vendor: str | None = None
    os_name: str | None = None            # best-guess OS (needs privileged scan to populate)
    os_accuracy: int | None = None        # nmap's confidence % in that OS guess
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    last_seen: str = field(default_factory=_now_iso)
    credentialed: Optional[CredentialedData] = None
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "mac": self.mac,
            "vendor": self.vendor,
            "os_name": self.os_name,
            "os_accuracy": self.os_accuracy,
            "last_seen": self.last_seen,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Scan:
    """Metadata for one run of the tool. Every host/finding is tied to a scan_id."""
    targets: str                          # what we were asked to scan, e.g. "192.168.1.0/24"
    started_at: str = field(default_factory=_now_iso)
    finished_at: str | None = None
    nmap_version: str = ""
    hosts: list[Host] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "targets": self.targets,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "nmap_version": self.nmap_version,
            "hosts": [h.to_dict() for h in self.hosts],
        }
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class CollectionStatus(str, Enum):
    SUCCESS       = "success"
    UNREACHABLE   = "unreachable"    # no path / port closed / timeout
    AUTH_FAILED   = "auth_failed"    # reached host, credentials rejected
    NOT_SUPPORTED = "not_supported"  # WinRM/SSH disabled on target
    ERROR         = "error"          # unexpected; see .message


@dataclass
class OSInfo:
    family: str                       # "windows" | "linux"
    product: str = ""                 # "Windows Server 2016 Standard" / "Ubuntu"
    version: str = ""                 # "10.0.14393" / "20.04"
    build: str = ""                   # "14393" / kernel "5.4.0-91-generic"
    architecture: str = ""


@dataclass
class Patch:
    identifier: str                   # HotFixID (KB…) or update id
    installed_on: Optional[str] = None  # raw string; parse in Phase 3


@dataclass
class AVProduct:
    name: str
    enabled: Optional[bool] = None       # real-time protection on?
    up_to_date: Optional[bool] = None    # signatures current?
    raw_state: Optional[int] = None      # SecurityCenter2 productState, for audit


@dataclass
class InstalledPackage:
    name: str
    version: str


@dataclass
class CredentialedData:
    """Result of one logged-in read of a single host."""
    status: CollectionStatus
    collected_at: datetime = field(default_factory=datetime.utcnow)
    message: str = ""                             # detail when status != SUCCESS
    os: Optional[OSInfo] = None
    patches: list[Patch] = field(default_factory=list)
    av_products: list[AVProduct] = field(default_factory=list)
    packages: list[InstalledPackage] = field(default_factory=list)