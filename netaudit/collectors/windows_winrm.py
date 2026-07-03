"""
collectors/windows_winrm.py — Phase 2

Read-only Windows collector over WinRM (pywinrm).

Reads (in ONE PowerShell round-trip that returns JSON):
  * OS product / version / build / architecture  (Win32_OperatingSystem)
  * installed hotfixes                           (Win32_QuickFixEngineering)
  * antivirus status                             (root/SecurityCenter2, with a
                                                  Get-MpComputerStatus fallback
                                                  for Windows Server)

Safety / accuracy notes:
  * Everything is a fixed query. Nothing changes target state.
  * Expected failures (bad creds, host down, WinRM disabled) map to a
    CollectionStatus; they do not raise.
  * Win32_QuickFixEngineering lists *installed* hotfixes, NOT "missing" ones.
    Real patch-gap detection = compare installed KBs against a baseline; that
    is a Phase 3 (enrichment) job. Don't let a report imply this proves the
    host is fully patched.
  * The productState AV decode is a community heuristic, not Microsoft-
    documented, so raw_state is always retained on the AVProduct for audit.
  * SecurityCenter2 exists on client Windows (10/11) but NOT on Server SKUs,
    hence the Defender fallback.

Transport: NTLM over 5985 by default. NTLM encrypts the message payload, so
this is not cleartext even without TLS. Set credential.use_tls=True to use
HTTPS/5986 instead (see the cert note in _endpoint()).

Requires: pip install pywinrm requests_ntlm
          (for Kerberos instead of NTLM: pip install pywinrm[kerberos])
"""

from __future__ import annotations

import json
from typing import Optional

import requests
from winrm import Session
from winrm.exceptions import (
    InvalidCredentialsError,
    WinRMError,
    WinRMTransportError,
)

from ..core.credentials import Credential
from ..core.models import (
    AVProduct,
    CollectionStatus,
    CredentialedData,
    OSInfo,
    Patch,
)
from .base import Collector

# One round-trip. $ErrorActionPreference keeps missing classes from aborting the
# whole script; we normalize the shape in Python afterwards.
_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'

$os = Get-CimInstance -ClassName Win32_OperatingSystem |
      Select-Object Caption, Version, BuildNumber, OSArchitecture

$hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering |
            Select-Object HotFixID, @{N='InstalledOn';E={[string]$_.InstalledOn}}

$av = @()
$sc = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
if ($sc) {
    $av = $sc | Select-Object `
        @{N='name';E={$_.displayName}}, `
        @{N='state';E={$_.productState}}, `
        @{N='source';E={'SecurityCenter2'}}
} else {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $av = @([PSCustomObject]@{
            name       = 'Windows Defender'
            rtp        = [bool]$mp.RealTimeProtectionEnabled
            sigAgeDays = [int]$mp.AntivirusSignatureAge
            source     = 'Defender'
        })
    }
}

[PSCustomObject]@{ os = $os; hotfixes = $hotfixes; av = $av } |
    ConvertTo-Json -Depth 5 -Compress
"""


class WindowsWinRMCollector(Collector):
    transport = "winrm"

    def collect(self, ip: str, credential: Credential,
                timeout: int = 30) -> CredentialedData:
        try:
            session = Session(
                target=self._endpoint(ip, credential),
                auth=(self._username(credential), credential.password),
                transport=credential.winrm_auth,          # "ntlm" | "kerberos"
                server_cert_validation="validate",         # see _endpoint() note
                operation_timeout_sec=timeout,
                read_timeout_sec=timeout + 10,
            )
            result = session.run_ps(_PS_SCRIPT)
        except InvalidCredentialsError:
            return CredentialedData(
                status=CollectionStatus.AUTH_FAILED,
                message="WinRM authentication rejected",
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as exc:
            return CredentialedData(
                status=CollectionStatus.UNREACHABLE,
                message=f"WinRM connect failed: {exc}",
            )
        except (WinRMTransportError, WinRMError) as exc:
            # Reached something, but WinRM refused / isn't configured as expected.
            return CredentialedData(
                status=CollectionStatus.NOT_SUPPORTED,
                message=f"WinRM not available: {exc}",
            )
        except Exception as exc:  # unexpected only
            return CredentialedData(
                status=CollectionStatus.ERROR,
                message=f"WinRM collection error: {exc}",
            )

        return self._parse(result)

    # --- connection helpers ---------------------------------------------------
    @staticmethod
    def _endpoint(ip: str, cred: Credential) -> str:
        if cred.use_tls:
            # HTTPS / 5986. server_cert_validation is set to "validate" above.
            # Internal WinRM listeners often use a SELF-SIGNED cert — the right
            # fix is to import that cert into your trust store. If you must, you
            # can relax validation by changing server_cert_validation to
            # "ignore" in collect() (weaker: drops MITM protection). Prefer
            # trusting the cert over ignoring it.
            return f"https://{ip}:{cred.port or 5986}/wsman"
        # HTTP / 5985 — NTLM/Kerberos still encrypt the payload.
        return f"http://{ip}:{cred.port or 5985}/wsman"

    @staticmethod
    def _username(cred: Credential) -> str:
        u = cred.username
        if cred.domain and "\\" not in u and "@" not in u:
            return f"{cred.domain}\\{u}"
        return u

    # --- parsing --------------------------------------------------------------
    def _parse(self, result) -> CredentialedData:
        out = (result.std_out or b"").decode("utf-8", "replace").strip()
        if not out or out == "null":
            err = (result.std_err or b"").decode("utf-8", "replace").strip()
            return CredentialedData(
                status=CollectionStatus.ERROR,
                message=f"Empty WinRM response (status {result.status_code}). {err}",
            )
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            return CredentialedData(
                status=CollectionStatus.ERROR,
                message=f"Could not parse WinRM JSON: {exc}",
            )

        return CredentialedData(
            status=CollectionStatus.SUCCESS,
            os=self._os(data.get("os")),
            patches=self._patches(data.get("hotfixes")),
            av_products=self._av(data.get("av")),
        )

    @staticmethod
    def _as_list(value) -> list:
        # ConvertTo-Json emits a single object (not a list) when there's one row.
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _os(os_obj) -> Optional[OSInfo]:
        if not os_obj:
            return None
        return OSInfo(
            family="windows",
            product=os_obj.get("Caption", "") or "",
            version=os_obj.get("Version", "") or "",
            build=str(os_obj.get("BuildNumber", "") or ""),
            architecture=os_obj.get("OSArchitecture", "") or "",
        )

    def _patches(self, hotfixes) -> list[Patch]:
        patches: list[Patch] = []
        for hf in self._as_list(hotfixes):
            kb = hf.get("HotFixID")
            if kb:
                patches.append(Patch(identifier=kb,
                                     installed_on=hf.get("InstalledOn") or None))
        return patches

    def _av(self, av_list) -> list[AVProduct]:
        products: list[AVProduct] = []
        seen: set = set()   # SecurityCenter2 often registers a product several
                            # times (one row per component GUID); collapse exact
                            # duplicates so a report shows each AV once.
        for entry in self._as_list(av_list):
            if entry.get("source") == "SecurityCenter2":
                state = entry.get("state")
                enabled, up_to_date = self._decode_product_state(state)
                product = AVProduct(
                    name=entry.get("name", "") or "Unknown AV",
                    enabled=enabled,
                    up_to_date=up_to_date,
                    raw_state=state if isinstance(state, int) else None,
                )
            else:  # Defender fallback (Windows Server path)
                age = entry.get("sigAgeDays")
                product = AVProduct(
                    name=entry.get("name", "Windows Defender"),
                    enabled=bool(entry.get("rtp")),
                    up_to_date=(age is not None and age <= 7),
                    raw_state=None,
                )

            key = (product.name, product.enabled, product.up_to_date,
                   product.raw_state)
            if key not in seen:
                seen.add(key)
                products.append(product)
        return products

    @staticmethod
    def _decode_product_state(state) -> tuple[Optional[bool], Optional[bool]]:
        """
        Decode a SecurityCenter2 productState into (enabled, up_to_date).

        productState as 6 hex digits = AABBCC:
            AA = security provider / product type
            BB = real-time protection: 0x10 / 0x11 -> ON, 0x00 / 0x01 -> OFF
            CC = signatures:           0x00 -> up to date, 0x10 -> out of date

        Community-reverse-engineered; not officially documented. raw_state is
        always kept on the AVProduct so a human can audit this interpretation.
        """
        try:
            h = f"{int(state):06x}"
        except (TypeError, ValueError):
            return None, None
        rtp_byte = int(h[2:4], 16)
        sig_byte = int(h[4:6], 16)
        enabled = rtp_byte in (0x10, 0x11)
        up_to_date = (sig_byte == 0x00)
        return enabled, up_to_date
