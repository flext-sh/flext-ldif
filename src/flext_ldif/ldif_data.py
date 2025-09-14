"""FLEXT LDIF Data - Test data and sample LDIF content.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar


class LdifSample:
    """LDIF sample data for testing."""

    BASIC_LDIF: ClassVar[str] = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
sn: TestUser

dn: cn=admin,dc=example,dc=com
cn: admin
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


class LdifTestData:
    """LDIF test data utilities."""

    @staticmethod
    def get_sample_entries() -> list[dict[str, list[str]]]:
        """Get sample LDIF entries for testing."""
        return [
            {
                "dn": ["cn=test,dc=example,dc=com"],
                "cn": ["test"],
                "objectClass": ["person"],
                "sn": ["TestUser"],
            },
            {
                "dn": ["cn=admin,dc=example,dc=com"],
                "cn": ["admin"],
                "objectClass": ["person"],
                "sn": ["AdminUser"],
            },
        ]

    @staticmethod
    def get_complex_entries() -> list[dict[str, list[str]]]:
        """Get complex LDIF entries for testing."""
        return [
            {
                "dn": ["cn=complex,dc=example,dc=com"],
                "cn": ["complex"],
                "objectClass": ["person"],
                "sn": ["ComplexUser"],
                "mail": ["complex@example.com"],
                "telephoneNumber": ["+1-555-123-4567"],
            },
            {
                "dn": ["cn=group,dc=example,dc=com"],
                "cn": ["group"],
                "objectClass": ["groupOfNames"],
                "member": ["cn=complex,dc=example,dc=com"],
            },
        ]


__all__ = ["LdifSample", "LdifTestData"]
