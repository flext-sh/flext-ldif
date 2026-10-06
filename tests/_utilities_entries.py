"""Real entry and LDIF fixture-content builders for tests.

Focused utility module split out of ``tests.utilities``; the public surface is
re-exported through ``tests.utilities`` (see ``TestsLdifEntryBuildersMixin``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, ClassVar

from tests import c, m, t

if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from pathlib import Path


class TestsLdifEntryBuildersMixin:
    """Builders for real entry models, LDIF content, and fixture metadata."""

    _FIXTURES_ROOT: ClassVar[Path] = c.Tests.FIXTURES_DIR
    _FILE_EXTENSION: ClassVar[str] = ".ldif"
    _fixture_metadata_cache: ClassVar[
        MutableMapping[Path, m.Tests.FixtureMetadata]
    ] = {}

    @staticmethod
    def create_real_entry(
        dn: str | None = None,
        attributes: t.MappingKV[str, t.StrSequence] | None = None,
        server_type: str = "generic",
    ) -> m.Ldif.Entry:
        """Create a real Entry model with valid data.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        entry_id = uuid.uuid4().hex[:8]
        payload_attrs = attributes or {
            "cn": [f"test-{entry_id}"],
            "sn": ["Test"],
            "mail": [f"test-{entry_id}@example.com"],
            "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
        }
        entry: m.Ldif.Entry = m.Ldif.Entry.model_validate({
            "dn": {"value": dn or f"cn=test-{entry_id},ou=users,dc=example,dc=com"},
            "attributes": {
                "attributes": {k: list(v) for k, v in payload_attrs.items()},
            },
            "server_type": server_type,
        })
        return entry

    @classmethod
    def orclaci_base_dn_entry(cls, dn: str = "cn=users,dc=ctbc") -> m.Ldif.Entry:
        """Build a real LDIF entry carrying an out-of-scope OID orclaci for
        # base-DN filter tests.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        return cls.create_real_entry(
            dn=dn,
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    ),
                ],
            },
        )

    @staticmethod
    def create_real_ldif_content(
        entries_count: int = 3,
        *,
        include_schema: bool = False,
    ) -> str:
        """Create real LDIF content for testing.

        Returns:
            The resulting ``str``.
        """
        blocks: list[str] = []
        if include_schema:
            blocks.append(
                "dn: cn=schema\n"
                "objectClass: top\n"
                "objectClass: ldapSubentry\n"
                "objectClass: subschema\n"
                "\n"
                "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX "
                "1.3.6.1.4.1.1466.115.121.1.15 )\n",
            )
        for index in range(entries_count):
            entry_id = uuid.uuid4().hex[:8]
            blocks.append(
                f"dn: cn=user-{entry_id},ou=users,dc=example,dc=com\n"
                "objectClass: person\n"
                "objectClass: organizationalPerson\n"
                "objectClass: inetOrgPerson\n"
                f"cn: User {entry_id}\n"
                f"sn: Test{index}\n"
                f"mail: user{entry_id}@example.com\n",
            )
        return "\n".join(blocks)

    @staticmethod
    def parametrize_real_data() -> t.SequenceOf[m.Tests.LdifTestData]:
        """Generate parametrized test data for comprehensive coverage.

        Returns:
            The resulting ``t.SequenceOf[m.Tests.LdifTestData]``.
        """
        return [
            m.Tests.LdifTestData(
                id=f"entry_{server_type}",
                server_type=server_type,
                dn=f"cn=test-{server_type},ou=users,dc=example,dc=com",
                attributes={
                    "cn": [f"test-{server_type}"],
                    "objectClass": ["person", "organizationalPerson"],
                },
            )
            for server_type in ("generic", *c.Tests.PARAMETRIZED_REAL_SERVERS)
        ]

    @classmethod
    def fixture_metadata(
        cls,
        server_type: t.Tests.FixtureServer,
        fixture_type: t.Tests.FixtureKind,
    ) -> m.Tests.FixtureMetadata:
        """Return metadata for one fixture file (cached per file path)."""
        file_path = cls.path(server_type, fixture_type)
        cached = cls._fixture_metadata_cache.get(file_path)
        if cached is not None:
            return cached
        content = cls.load(server_type, fixture_type)
        lines = content.splitlines()
        metadata = m.Tests.FixtureMetadata(
            server_type=server_type,
            fixture_type=fixture_type,
            file_path=file_path,
            line_count=len(lines),
            entry_count=sum(1 for line in lines if line.strip().startswith("dn:")),
            size_bytes=file_path.stat().st_size,
        )
        cls._fixture_metadata_cache[file_path] = metadata
        return metadata
