"""Tests for the RFC server hook contract.

The server bases require concrete capability implementations at construction;
the RFC servers provide the default behavior every
vendor server inherits.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif
from flext_ldif.servers import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    FlextLdifServersRfc,
)
from tests import c, m, tm


class TestsFlextLdifRfcServers:
    """Behavioral contract tests for the RFC server defaults and the base hooks."""

    ATTRIBUTE_DEFINITION = (
        "( 2.5.4.3 NAME 'cn' DESC 'common name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )
    SUP_ONLY_ATTRIBUTE_DEFINITION = "( 2.5.4.4 NAME 'sn' SUP name )"
    OBJECTCLASS_DEFINITION = (
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
    )
    LDIF_RECORD = "dn: cn=alice,dc=example,dc=com\nobjectclass: person\ncn: alice\n"

    @classmethod
    def _parsed_attribute(cls) -> m.Ldif.SchemaAttribute:
        return (
            FlextLdifServersRfc
            .Schema()
            .parse_attribute(cls.ATTRIBUTE_DEFINITION)
            .unwrap()
        )

    @classmethod
    def _parsed_objectclass(cls) -> m.Ldif.SchemaObjectClass:
        return (
            FlextLdifServersRfc
            .Schema()
            .parse_objectclass(cls.OBJECTCLASS_DEFINITION)
            .unwrap()
        )

    @staticmethod
    def test_rfc_acl_resolves_rfc_acl_attributes() -> None:
        """The RFC ACL server reports the configured RFC ACL attributes."""
        acl = FlextLdif().acl(c.Ldif.ServerTypes.RFC).unwrap()
        tm.that(acl.resolve_acl_attributes(), eq=list(c.Ldif.RFC_ACL_ATTRIBUTES))
        for attribute_name in c.Ldif.RFC_ACL_ATTRIBUTES:
            tm.ok(acl.matches_acl_attribute(attribute_name.upper()))

    @classmethod
    def test_rfc_acl_ignores_schema_definitions(cls) -> None:
        """The RFC ACL server is not aware of schema definitions."""
        acl = FlextLdifServersRfc.Acl()
        tm.fail(acl.can_handle_attribute(cls._parsed_attribute()))
        tm.fail(acl.can_handle_objectclass(cls._parsed_objectclass()))

    @staticmethod
    def test_rfc_acl_round_trips_raw_acl() -> None:
        """The RFC ACL server parses and writes the raw ACL unchanged."""
        acl = FlextLdif().acl(c.Ldif.ServerTypes.RFC).unwrap()
        raw_acl = "access to * by * read"
        parsed = acl.parse_server(raw_acl).unwrap()
        tm.that(parsed.raw_acl, eq=raw_acl)
        tm.that(acl.write(parsed).unwrap(), eq=raw_acl)

    @classmethod
    def test_rfc_entry_ignores_schema_definitions(cls) -> None:
        """The RFC entry server is not aware of schema definitions."""
        entry = FlextLdifServersRfc.Entry()
        tm.fail(entry.can_handle_attribute(cls._parsed_attribute()))
        tm.fail(entry.can_handle_objectclass(cls._parsed_objectclass()))

    @classmethod
    def test_rfc_entry_parses_and_writes_record(cls) -> None:
        """The RFC entry server parses one record and writes it back."""
        entry = FlextLdif().entry(c.Ldif.ServerTypes.RFC).unwrap()
        entries = entry.parse_server(cls.LDIF_RECORD).unwrap()
        tm.that(len(entries), eq=1)
        tm.ok(entries[0].dn is not None)
        written = entry.write(entries[0]).unwrap()
        tm.that(written, has="cn=alice,dc=example,dc=com")
        tm.that(written, has="alice")

    @classmethod
    def test_rfc_schema_parses_and_writes_definitions(cls) -> None:
        """The RFC schema server round-trips attribute and objectClass definitions."""
        schema = FlextLdif().schema_server(c.Ldif.ServerTypes.RFC).unwrap()
        attribute = cls._parsed_attribute()
        tm.that(attribute.oid, eq="2.5.4.3")
        tm.that(schema.write_attribute(attribute).unwrap(), has="NAME 'cn'")
        objectclass = cls._parsed_objectclass()
        tm.that(objectclass.oid, eq="2.5.6.6")
        tm.that(schema.write_objectclass(objectclass).unwrap(), has="NAME 'person'")

    @classmethod
    def test_rfc_schema_parses_definitions_without_syntax_clause(cls) -> None:
        """An attribute that inherits its syntax from SUP parses without SYNTAX."""
        attribute = (
            FlextLdifServersRfc
            .Schema()
            .parse_attribute(cls.SUP_ONLY_ATTRIBUTE_DEFINITION)
            .unwrap()
        )
        tm.that(attribute.oid, eq="2.5.4.4")
        tm.that(attribute.name, eq="sn")
        tm.that(attribute.sup, eq="name")
        tm.that(attribute.syntax, eq=None)

    @staticmethod
    def test_base_acl_hook_raises_when_not_redefined() -> None:
        """An incomplete ACL capability cannot be constructed."""
        with pytest.raises(TypeError, match=r"abstract.*_parse_acl"):
            FlextLdifServersBaseSchemaAcl()

    @staticmethod
    def test_base_entry_hook_raises_when_not_redefined() -> None:
        """An incomplete entry capability cannot be constructed."""
        with pytest.raises(TypeError, match=r"abstract.*_parse_content"):
            FlextLdifServersBaseEntry()

    @staticmethod
    def test_base_schema_hook_raises_when_not_redefined() -> None:
        """An incomplete schema capability cannot be constructed."""
        with pytest.raises(TypeError, match=r"abstract.*can_handle_attribute"):
            FlextLdifServersBaseSchema()
