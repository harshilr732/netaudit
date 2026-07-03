"""
core/credentials.py — Phase 2

Credential model + a subnet-based store, so ONE read-only service account can
cover a whole subnet (mirrors the guide's "one AD service account + GPO covers
hundreds of hosts" idea).

Security rules baked in:
  * Secrets are NEVER hardcoded here. Config holds the *name* of an environment
    variable; the actual secret is read from os.environ at load time.
  * Credential.__repr__ is overridden so a password can never leak into a log
    line, exception traceback, or console dump.
  * Give the audit account the LEAST privilege that still lets it read patch/AV
    state (a read-only WMI / local-admin-equivalent-read account, or a
    non-privileged SSH login that can run dpkg-query/rpm).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address, ip_network
from typing import Optional


class Transport(str, Enum):
    SSH = "ssh"
    WINRM = "winrm"


@dataclass(frozen=True)
class Credential:
    transport: Transport
    username: str

    # Exactly one auth secret is used:
    #   SSH   -> ssh_key_path (preferred) OR password
    #   WinRM -> password
    password: Optional[str] = None
    ssh_key_path: Optional[str] = None

    # Windows / WinRM only
    domain: Optional[str] = None
    winrm_auth: str = "ntlm"      # "ntlm" | "kerberos". Avoid "basic".
    use_tls: bool = False         # WinRM over HTTPS (5986) when True

    port: Optional[int] = None    # default resolved by the collector
                                  # (22 ssh / 5985 winrm-http / 5986 winrm-https)

    def __repr__(self) -> str:
        # NEVER include password / key material here.
        return (f"Credential(transport={self.transport.value}, "
                f"username={self.username!r}, domain={self.domain!r})")


@dataclass
class CredentialRule:
    network: str                  # CIDR, e.g. "10.0.10.0/24" or "192.168.1.50/32"
    credential: Credential


class CredentialStore:
    """Resolves a host IP to the first matching subnet rule."""

    def __init__(self, rules: list[CredentialRule]):
        # Pre-parse networks once; keep insertion order so more-specific rules
        # can be placed first by the caller.
        self._rules = [(ip_network(r.network, strict=False), r.credential)
                       for r in rules]

    def for_host(self, ip: str) -> Optional[Credential]:
        addr = ip_address(ip)
        for net, cred in self._rules:
            if addr in net:
                return cred
        return None


def load_store_from_config(path: str) -> CredentialStore:
    """
    Load credential rules from a JSON file whose secrets are ENV-VAR REFERENCES,
    not literals. Example config (gitignore this file):

    {
      "rules": [
        {
          "network": "10.0.10.0/24",
          "transport": "winrm",
          "username": "AUDIT\\svc-audit",
          "domain": "AUDIT",
          "winrm_auth": "ntlm",
          "use_tls": true,
          "secret_env": "AUDIT_WIN_PW"
        },
        {
          "network": "10.0.20.0/24",
          "transport": "ssh",
          "username": "svc-audit",
          "ssh_key_path": "/opt/netaudit/keys/audit_ed25519"
        }
      ]
    }

    The Windows rule's password comes from os.environ["AUDIT_WIN_PW"].
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    rules: list[CredentialRule] = []
    for entry in raw.get("rules", []):
        transport = Transport(entry["transport"])

        password = None
        secret_env = entry.get("secret_env")
        if secret_env:
            password = os.environ.get(secret_env)
            if password is None:
                raise RuntimeError(
                    f"Credential for {entry['network']} references env var "
                    f"{secret_env!r}, but it is not set."
                )

        cred = Credential(
            transport=transport,
            username=entry["username"],
            password=password,
            ssh_key_path=entry.get("ssh_key_path"),
            domain=entry.get("domain"),
            winrm_auth=entry.get("winrm_auth", "ntlm"),
            use_tls=entry.get("use_tls", False),
            port=entry.get("port"),
        )
        rules.append(CredentialRule(network=entry["network"], credential=cred))

    return CredentialStore(rules)
