"""
scanners/nmap_scanner.py — the discovery + service-detection engine.

Design choice: we call the real `nmap` binary via subprocess and ask it for XML
output (`-oX -`, meaning "write XML to stdout"), then parse that XML ourselves
with Python's built-in xml.etree. We do NOT use the `python-nmap` PyPI package.

Why do it this way?
  * Zero extra dependencies — xml.etree is in the standard library.
  * Nmap's XML is a stable, documented contract. Parsing it directly means we
    see *everything* nmap reports, not just the subset a wrapper library exposes.
  * It's the same pattern we'll reuse for Nuclei (run a tool, parse its output),
    so you learn one technique that transfers.

READ-ONLY REMINDER: every flag we pass to nmap here is discovery/detection only
(-sn, -sV, -O, -sC). Nothing here exploits, brute-forces, or modifies a target.
Keep it that way — that read-only property is the tool's core safety guarantee.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from netaudit.core.models import Confidence, Finding, Host, Service, Severity

# Matches CVE identifiers embedded in NSE script output, e.g. "CVE-2017-0143".
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _scripts_to_findings(parent_el, port: int | None) -> list[Finding]:
    """
    Turn <script> elements (from a <port> or a <hostscript>) into Findings.

    We ran only the "vuln and safe" NSE category (see NmapScanner), so every
    script here is a vulnerability *detector*. Honesty rules for severity:
      * NSE does NOT report a CVSS score, so severity stays UNKNOWN here.
        Phase 3 fills it in by looking the CVE up in the NVD database.
      * Confidence, though, we CAN set: if the script literally reports
        "VULNERABLE", it confirmed the issue on the host -> CONFIRMED.
        Otherwise it's a weaker signal -> FIRM.
    Setting severity we don't actually know would be over-claiming — exactly
    what the build guide warns against.
    """
    findings: list[Finding] = []
    for script in parent_el.findall("script"):
        script_id = script.get("id", "unknown-script")
        output = (script.get("output") or "").strip()
        confirmed = "VULNERABLE" in output.upper()
        cves = sorted(set(m.upper() for m in _CVE_RE.findall(output)))

        # SIGNAL FILTER: nmap runs some *informational* scripts as dependencies
        # of the real vuln scripts (e.g. http-server-header just prints the
        # server banner). Those aren't findings. We only record a script result
        # as a finding if it actually signals a vulnerability — i.e. it says
        # "VULNERABLE" or cites a CVE. This keeps the findings list honest
        # instead of padding it with banner noise (which we already capture as
        # the service's product/version anyway).
        if not confirmed and not cves:
            continue

        findings.append(
            Finding(
                source="nmap-nse",
                title=script_id,
                severity=Severity.UNKNOWN,
                confidence=Confidence.CONFIRMED if confirmed else Confidence.FIRM,
                port=port,
                cve=cves[0] if cves else "",
                description=output,
            )
        )
    return findings


class NmapError(RuntimeError):
    """Raised when nmap is missing or the scan fails."""


def _require_nmap() -> str:
    """Return the path to the nmap binary, or explain clearly that it's missing."""
    path = shutil.which("nmap")
    if not path:
        raise NmapError(
            "nmap is not installed or not on your PATH.\n"
            "  - Windows: download from https://nmap.org/download.html\n"
            "  - Debian/Ubuntu: sudo apt install nmap\n"
            "  - macOS: brew install nmap"
        )
    return path


def parse_nmap_xml(xml_text: str) -> tuple[list[Host], str]:
    """
    Turn nmap's XML output into our Host/Service objects.

    Kept as a standalone function (not a method) on purpose: it means we can unit
    -test parsing against a saved XML file without ever running a real scan.
    Returns (hosts, nmap_version).
    """
    root = ET.fromstring(xml_text)
    nmap_version = root.get("version", "")
    hosts: list[Host] = []

    for host_el in root.findall("host"):
        # State: is the host up?
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"
        if state == "down":
            continue  # skip hosts that never answered

        ip = None
        mac = None
        vendor = None
        for addr in host_el.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif addrtype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if not ip:
            continue  # can't do anything useful without an IP

        # Hostname (nmap may report several; take the first)
        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        # OS guess (only present if you ran with -O and had privileges)
        os_name = None
        os_accuracy = None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name")
                acc = match.get("accuracy")
                os_accuracy = int(acc) if acc and acc.isdigit() else None

        # Services (open ports)
        services: list[Service] = []
        findings: list[Finding] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                pstate_el = port_el.find("state")
                pstate = pstate_el.get("state", "unknown") if pstate_el is not None else "unknown"
                if pstate == "closed":
                    continue

                svc_el = port_el.find("service")
                cpes = [c.text for c in port_el.findall("service/cpe") if c.text]
                portid = int(port_el.get("portid", "0"))

                services.append(
                    Service(
                        port=portid,
                        protocol=port_el.get("protocol", "tcp"),
                        state=pstate,
                        name=(svc_el.get("name", "") if svc_el is not None else ""),
                        product=(svc_el.get("product", "") if svc_el is not None else ""),
                        version=(svc_el.get("version", "") if svc_el is not None else ""),
                        extra_info=(svc_el.get("extrainfo", "") if svc_el is not None else ""),
                        cpe=cpes,
                    )
                )
                # NSE scripts that ran against THIS port
                findings.extend(_scripts_to_findings(port_el, portid))

        # NSE scripts that ran against the host as a whole (e.g. smb-vuln-*)
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            findings.extend(_scripts_to_findings(hostscript_el, None))

        hosts.append(
            Host(
                ip=ip,
                hostname=hostname,
                state=state,
                mac=mac,
                vendor=vendor,
                os_name=os_name,
                os_accuracy=os_accuracy,
                services=services,
                findings=findings,
            )
        )

    return hosts, nmap_version


class NmapScanner:
    """Thin, safe wrapper around the nmap binary."""

    def __init__(self, timeout: int = 900):
        self.nmap_path = _require_nmap()
        self.timeout = timeout  # seconds; stops a runaway scan from hanging forever

    def _build_command(
        self,
        targets: list[str],
        ports: str | None,
        service_detection: bool,
        os_detection: bool,
        default_scripts: bool,
        vuln_scripts: bool,
        discovery_only: bool,
    ) -> list[str]:
        cmd = [self.nmap_path, "-oX", "-"]  # XML to stdout

        if discovery_only:
            cmd.append("-sn")               # ping scan: who's alive, no port scan
        else:
            if service_detection:
                cmd.append("-sV")           # probe versions of open services
            if os_detection:
                cmd.append("-O")            # OS fingerprint (needs admin/root)
            if default_scripts:
                cmd.append("-sC")           # run nmap's *default* safe NSE scripts
            if vuln_scripts:
                # SAFETY: run only scripts that are in the "vuln" category AND
                # marked "safe". The full "vuln" category also contains INTRUSIVE
                # scripts — e.g. http-slowloris literally performs a denial-of-
                # service. Your build guide forbids DoS / anything that could
                # destabilize a target, so we exclude the intrusive ones by
                # requiring "and safe". This keeps the whole tool read-only.
                cmd.extend(["--script", "vuln and safe"])
            if ports:
                cmd.extend(["-p", ports])   # e.g. "1-1000" or "22,80,443"

        cmd.extend(targets)
        return cmd

    def scan(
        self,
        targets: list[str],
        ports: str | None = None,
        service_detection: bool = True,
        os_detection: bool = False,
        default_scripts: bool = False,
        vuln_scripts: bool = False,
        discovery_only: bool = False,
    ) -> tuple[list[Host], str]:
        """
        Run nmap and return (hosts, nmap_version).

        `targets` is a list of IPs / hostnames / CIDR ranges you are AUTHORIZED
        to scan. e.g. ["127.0.0.1"], ["192.168.1.0/24"], ["scanme.nmap.org"].
        """
        if not targets:
            raise NmapError("No scan targets provided.")

        cmd = self._build_command(
            targets, ports, service_detection, os_detection,
            default_scripts, vuln_scripts, discovery_only,
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise NmapError(f"nmap timed out after {self.timeout}s. Try a smaller range or fewer ports.")

        if proc.returncode != 0 and not proc.stdout.strip():
            # Common cause: -O / -sS without admin/root privileges.
            hint = ""
            if os_detection and ("requires root" in proc.stderr.lower() or "privilege" in proc.stderr.lower()):
                hint = "\nHint: OS detection (-O) needs Administrator (Windows) or sudo/root (Linux)."
            raise NmapError(f"nmap failed:\n{proc.stderr.strip()}{hint}")

        return parse_nmap_xml(proc.stdout)
