"""
collectors/linux_ssh.py — Phase 2

Read-only Linux collector over SSH (paramiko).

Reads:
  * OS product/version   (/etc/os-release)
  * kernel + architecture (uname)
  * installed packages    (dpkg-query on Debian/Ubuntu, else rpm on RHEL-family)

Safety notes:
  * Every command below is a FIXED constant. No host-derived data is ever
    interpolated into a command string, so there is no shell-injection surface.
  * Expected failures (auth rejected, timeout, unreachable) map to a
    CollectionStatus; they do not raise.
  * Host-key verification: we load the system known_hosts and REJECT unknown
    hosts by default (safe). For a throwaway lab bench you own, you may swap in
    AutoAddPolicy (see the commented line) — but that drops MITM protection, so
    don't ship it against a client subnet. For production, pre-seed known_hosts.

Requires: pip install paramiko
"""

from __future__ import annotations

import socket

import paramiko

from ..core.credentials import Credential
from ..core.models import (
    CollectionStatus,
    CredentialedData,
    InstalledPackage,
    OSInfo,
)
from .base import Collector

# --- fixed, read-only commands -------------------------------------------------
_OS_RELEASE = "cat /etc/os-release 2>/dev/null"
_KERNEL = "uname -r"
_ARCH = "uname -m"
# Debian/Ubuntu. \t and \n are passed through for dpkg to interpret.
_DPKG = r"dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null"
# RHEL/Rocky/Alma/SUSE fallback.
_RPM = r"rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null"


class LinuxSSHCollector(Collector):
    transport = "ssh"

    def collect(self, ip: str, credential: Credential,
                timeout: int = 15) -> CredentialedData:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        # Lab-only override (drops MITM protection — do not use in production):
        # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # --- connect ----------------------------------------------------------
        try:
            connect_kwargs = dict(
                hostname=ip,
                port=credential.port or 22,
                username=credential.username,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            if credential.ssh_key_path:
                connect_kwargs["key_filename"] = credential.ssh_key_path
            else:
                connect_kwargs["password"] = credential.password
            client.connect(**connect_kwargs)
        except paramiko.AuthenticationException:
            return CredentialedData(
                status=CollectionStatus.AUTH_FAILED,
                message="SSH authentication rejected",
            )
        except (socket.timeout, socket.error, paramiko.SSHException) as exc:
            return CredentialedData(
                status=CollectionStatus.UNREACHABLE,
                message=f"SSH connect failed: {exc}",
            )

        # --- collect ----------------------------------------------------------
        try:
            os_info = self._os_info(client, timeout)
            packages = self._packages(client, timeout)
            return CredentialedData(
                status=CollectionStatus.SUCCESS,
                os=os_info,
                packages=packages,
            )
        except Exception as exc:  # unexpected only — never abort the whole run
            return CredentialedData(
                status=CollectionStatus.ERROR,
                message=f"SSH collection error: {exc}",
            )
        finally:
            client.close()

    # --- helpers --------------------------------------------------------------
    @staticmethod
    def _run(client: paramiko.SSHClient, command: str, timeout: int) -> str:
        _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")

    def _os_info(self, client, timeout) -> OSInfo:
        fields: dict[str, str] = {}
        for line in self._run(client, _OS_RELEASE, timeout).splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip().strip('"')

        kernel = self._run(client, _KERNEL, timeout).strip()
        arch = self._run(client, _ARCH, timeout).strip()

        return OSInfo(
            family="linux",
            product=fields.get("NAME", "Linux"),
            version=fields.get("VERSION_ID", ""),
            build=kernel,
            architecture=arch,
        )

    def _packages(self, client, timeout) -> list[InstalledPackage]:
        out = self._run(client, _DPKG, timeout)
        if not out.strip():
            out = self._run(client, _RPM, timeout)   # RHEL-family fallback

        packages: list[InstalledPackage] = []
        for line in out.splitlines():
            if "\t" in line:
                name, _, version = line.partition("\t")
                name, version = name.strip(), version.strip()
                if name:
                    packages.append(InstalledPackage(name=name, version=version))
        return packages
