"""FLEXT LDIF Test Samples - Sample data for testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar


class FlextLdifTestSamples:
    """LDIF sample data for testing."""

    BASIC_LDIF: ClassVar[str] = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
sn: TestUser

dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
cn: REDACTED_LDAP_BIND_PASSWORD
objectClass: person
sn: AdminUser
"""

    COMPLEX_LDIF: ClassVar[str] = """dn: cn=complex,dc=example,dc=com
cn: complex
objectClass: person
sn: ComplexUser
mail: complex@example.com
telephoneNumber: +1-555-123-4567

dn: cn=group,dc=example,dc=com
cn: group
objectClass: groupOfNames
member: cn=complex,dc=example,dc=com
"""

    INVALID_LDIF: ClassVar[str] = """cn: test
objectClass: person
sn: TestUser
"""

    @property
    def description(self) -> str:
        """Sample description."""
        return "Basic LDIF sample"

    @property
    def content(self) -> str:
        """Sample content."""
        return self.BASIC_LDIF


__all__ = ["FlextLdifTestSamples"]
