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

    @property
    def description(self) -> str:
        """Sample description for test compatibility."""
        return "Basic LDIF sample"

    @property
    def content(self) -> str:
        """Sample content for test compatibility."""
        return self.BASIC_LDIF


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

    @staticmethod
    def all_samples() -> dict[str, LdifSample]:
        """Get all samples for test compatibility."""
        sample = LdifSample()
        return {
            "basic": sample,
            "complex": sample,
            "invalid": sample,
        }

    @staticmethod
    def large_dataset(num_entries: int) -> str:
        """Generate large dataset for test compatibility."""
        entries = [
            f"""dn: cn=user{i},dc=example,dc=com
cn: user{i}
objectClass: person
sn: User{i}
"""
            for i in range(num_entries)
        ]
        return "\n".join(entries)

    @staticmethod
    def invalid_data() -> str:
        """Get invalid data for test compatibility."""
        return LdifSample.INVALID_LDIF


__all__ = ["LdifSample", "LdifTestData"]
