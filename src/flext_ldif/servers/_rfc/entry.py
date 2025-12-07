"""RFC 2849 Compliant LDIF Entry Parser and Writer for flext-ldif.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC 2849 baseline LDIF entry parsing and manipulation.
Server-specific entry handling extends this RFC base implementation.

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

from flext_core import FlextLogger, r

from flext_ldif.models import m
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServersRfcEntry(FlextLdifServersBase.Entry):
    """RFC 2849 Compliant LDIF Entry Processing.

    Provides baseline entry parsing, validation, and manipulation
    following RFC 2849 LDIF format specification.

    Features:
    - RFC 2849 compliant LDIF parsing
    - Entry validation and transformation
    - Safe attribute handling
    - DN normalization

    """

    __doc_inline__ = True

    def __init__(self) -> None:
        """Initialize RFC LDIF Entry processor."""
        super().__init__()

    def parse(self, dn: str, attributes: dict[str, list[str]]) -> r[m.Ldif.Entry]:
        """Parse LDIF entry from DN and attributes.

        Args:
            dn: Distinguished name (RFC 4512 format)
            attributes: LDAP attributes (case-insensitive keys)

        Returns:
            FlextResult containing parsed Entry or error

        """
        if not dn or not isinstance(dn, str):
            return r.fail(f"Invalid DN: {dn}")
        if not attributes or not isinstance(attributes, dict):
            return r.fail(f"Invalid attributes: {attributes}")

        try:
            entry = m.Ldif.Entry(dn=dn.strip(), attributes=attributes)
            return r.ok(entry)
        except Exception as e:
            return r.fail(f"Failed to parse entry {dn}: {e}")

    def validate(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Validate RFC 2849 compliance.

        Args:
            entry: Entry to validate

        Returns:
            FlextResult containing validated Entry or error

        """
        if not entry or not isinstance(entry, m.Ldif.Entry):
            return r.fail(f"Invalid entry: {entry}")
        if not entry.dn or not isinstance(entry.dn, str):
            return r.fail(f"Invalid DN in entry: {entry.dn}")
        if not entry.attributes or not isinstance(entry.attributes, dict):
            return r.fail(f"Invalid attributes in entry: {entry.attributes}")

        return r.ok(entry)


__all__ = ["FlextLdifServersRfcEntry"]
