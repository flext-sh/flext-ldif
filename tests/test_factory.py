"""Automated Test Factory for Real Data Generation.

This module provides automated factories for generating real test data
following the strict type system architecture rules.
"""

from __future__ import annotations

import uuid
from typing import Any

from tests import m


class FlextLdifTestFactory:
    """Automated factory for generating real test data."""

    @staticmethod
    def create_real_entry(
        dn: str | None = None,
        attributes: dict[str, list[str]] | None = None,
        server_type: str = "generic",
    ) -> m.Ldif.Entry:
        """Create a real Entry model with valid data."""
        if dn is None:
            dn = f"cn=test-{uuid.uuid4().hex[:8]},ou=users,dc=example,dc=com"

        if attributes is None:
            attributes = {
                "cn": [f"test-{uuid.uuid4().hex[:8]}"],
                "sn": ["Test"],
                "mail": [f"test-{uuid.uuid4().hex[:8]}@example.com"],
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
            }

        return m.Ldif.Entry(
            dn=dn, attributes=m.Ldif.AttributesDict(attributes), server_type=server_type
        )

    @staticmethod
    def create_real_ldif_content(
        entries_count: int = 3, *, include_schema: bool = False
    ) -> str:
        """Create real LDIF content for testing."""
        lines = []

        if include_schema:
            lines.extend([
                "dn: cn=schema",
                "objectClass: top",
                "objectClass: ldapSubentry",
                "objectClass: subschema",
                "",
                "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                "",
            ])

        for i in range(entries_count):
            entry_id = uuid.uuid4().hex[:8]
            lines.extend([
                f"dn: cn=user-{entry_id},ou=users,dc=example,dc=com",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                f"cn: User {entry_id}",
                f"sn: Test{i}",
                f"mail: user{entry_id}@example.com",
                "",
            ])

        return "\n".join(lines)

    @staticmethod
    def parametrize_real_data() -> list[dict[str, Any]]:
        """Generate parametrized test data for comprehensive coverage."""
        # Basic entry variations
        return [
            {
                "id": f"entry_{server_type}",
                "server_type": server_type,
                "dn": f"cn=test-{server_type},ou=users,dc=example,dc=com",
                "attributes": {
                    "cn": [f"test-{server_type}"],
                    "objectClass": ["person", "organizationalPerson"],
                },
            }
            for server_type in ["generic", "openldap", "ad", "oid", "oud"]
        ]
