"""
collectors/base.py — Phase 2

The shared contract every collector honours:

  * collect() is READ-ONLY. It runs fixed query commands, never anything that
    changes target state.
  * collect() NEVER raises for an *expected* failure (host down, wrong creds,
    service disabled). It returns CredentialedData with the right
    CollectionStatus so one bad host can't abort a whole run.
  * Only genuinely unexpected bugs should propagate — and even those are caught
    by the collector and mapped to CollectionStatus.ERROR.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.credentials import Credential
from ..core.models import CredentialedData


class Collector(ABC):
    transport: str = ""          # "ssh" | "winrm" — set by each subclass

    @abstractmethod
    def collect(self, ip: str, credential: Credential,
                timeout: int = 15) -> CredentialedData:
        """Log in read-only and return normalized CredentialedData."""
        raise NotImplementedError
