"""FLEXT LDIF Test Data - Test data utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.test_samples import FlextLdifTestSamples


class FlextLdifTestData:
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
                "dn": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
                "cn": ["REDACTED_LDAP_BIND_PASSWORD"],
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
    def all_samples() -> dict[str, FlextLdifTestSamples]:
        """Get all samples."""
        sample = FlextLdifTestSamples()
        return {
            "basic": sample,
            "complex": sample,
            "invalid": sample,
        }

    @staticmethod
    def large_dataset(num_entries: int) -> str:
        """Generate large dataset."""
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
        """Get invalid data."""
        return FlextLdifTestSamples.INVALID_LDIF


__all__ = ["FlextLdifTestData"]
