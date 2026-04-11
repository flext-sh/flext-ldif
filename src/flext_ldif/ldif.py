"""Lowercase public LDIF facade alias."""

from __future__ import annotations

from flext_ldif.api import FlextLdif


class ldif(FlextLdif):  # noqa: N801 - public package contract requires lowercase alias
    """Lowercase public facade preserving historical construction style."""


__all__: list[str] = []
