"""Behavioral integration tests for OID (Oracle Internet Directory) LDIF.

Exercises the public LDIF client contract against real OID fixtures:
- Parsing OID schema/entry fixtures returns a successful ``r[ParseResponse]``.
- Oracle-specific schema definitions and operational attributes survive parsing.
- A parse -> write -> parse round-trip preserves entry count, DNs and ACL values.

All assertions target observable public behaviour (returned models, their
public fields and computed accessors) — never private state or collaborators.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import p, t, u

ORACLE_OID_PREFIX = "2.16.840.1.113894"


class TestsFlextLdifOidIntegration:
    """Behavioral contract tests for OID LDIF parsing and round-trip.

    Uses shared fixtures (``api``, ``oid_schema_fixture``,
    ``oid_integration_fixture``) declared in ``tests/unit/fixtures.py``.
    """

    @staticmethod
    def _entries(api: p.Ldif.Client, content: str) -> t.SequenceOf[p.Ldif.Entry]:
        """Parse ``content`` through the public client and return its entries."""
        response: p.Ldif.ParseResponse = u.Tests.assert_success(
            api.parse_ldif(content), error_msg="OID fixture parsing failed"
        )
        return response.entries

    @staticmethod
    def _schema_definitions(
        entry: p.Ldif.Entry, attribute_name: str
    ) -> t.SequenceOf[str]:
        """Return the raw schema definition strings for ``attribute_name``.

        Reads through the public ``attributes_dict`` protocol accessor, which
        is case-preserving; the RFC schema keys are camelCase.
        """
        attrs: t.MutableStrSequenceMapping = entry.attributes_dict
        return attrs.get(attribute_name, [])

    @staticmethod
    def _attribute_value_count(entry: p.Ldif.Entry, attribute_name: str) -> int:
        """Count values held under ``attribute_name`` via the public contract."""
        return len(entry.attributes_dict.get(attribute_name, []))

    @classmethod
    def _roundtrip(
        cls, api: p.Ldif.Client, entries: t.SequenceOf[p.Ldif.Entry]
    ) -> t.SequenceOf[p.Ldif.Entry]:
        """Write ``entries`` and re-parse the produced LDIF text."""
        written: p.Ldif.WriteResponse = u.Tests.assert_success(
            api.write(list(entries)), error_msg="writing OID entries failed"
        )
        assert written.content is not None
        return cls._entries(api, written.content)

    # ----------------------------------------------------------------- schema

    def test_parse_schema_fixture_yields_entries_with_dns(
        self, api: p.Ldif.Client, oid_schema_fixture: str
    ) -> None:
        """Parsing the OID schema returns entries, each exposing a DN."""
        entries = self._entries(api, oid_schema_fixture)

        assert entries, "OID schema produced no entries"
        assert all(entry.dn_str for entry in entries), (
            "every parsed schema entry must expose a non-empty DN"
        )

    @pytest.mark.parametrize(
        "definition_attr",
        ["attributeTypes", "objectClasses"],
        ids=["attribute-types", "object-classes"],
    )
    def test_oracle_definitions_detected_in_parsed_schema(
        self, api: p.Ldif.Client, oid_schema_fixture: str, definition_attr: str
    ) -> None:
        """Oracle-namespaced schema definitions are present after parsing.

        Stronger than a mere ``>= 0`` smoke check: the OID schema fixture is
        Oracle's own, so at least one definition must carry the Oracle OID arc.
        """
        entries = self._entries(api, oid_schema_fixture)
        schema_entry = entries[0]

        definitions = self._schema_definitions(schema_entry, definition_attr)
        oracle_definitions = [
            definition for definition in definitions if ORACLE_OID_PREFIX in definition
        ]

        assert oracle_definitions, (
            f"no Oracle {definition_attr} (OID {ORACLE_OID_PREFIX}.*) parsed"
        )

    # ------------------------------------------------------------- entry data

    def test_parse_integration_fixture_yields_full_dataset(
        self, api: p.Ldif.Client, oid_integration_fixture: str
    ) -> None:
        """The integration fixture parses into a large, real dataset."""
        entries = self._entries(api, oid_integration_fixture)

        min_expected_entries = 100
        assert len(entries) > min_expected_entries, (
            f"expected > {min_expected_entries} entries, got {len(entries)}"
        )

    @pytest.mark.parametrize(
        "attribute_name",
        ["orclaci", "orclentrylevelaci", "orclisenabled", "orclpassword"],
        ids=["acl", "entry-level-acl", "is-enabled", "password"],
    )
    def test_oracle_attribute_preserved_in_parsing(
        self, api: p.Ldif.Client, oid_integration_fixture: str, attribute_name: str
    ) -> None:
        """Oracle-specific attributes survive parsing on at least one entry."""
        entries = self._entries(api, oid_integration_fixture)

        entries_with_attribute = sum(
            1 for entry in entries if attribute_name in entry.attributes_dict
        )

        assert entries_with_attribute > 0, (
            f"no parsed entry carries the {attribute_name} attribute"
        )

    # --------------------------------------------------------------- roundtrip

    def test_roundtrip_preserves_entry_count(
        self, api: p.Ldif.Client, oid_integration_fixture: str
    ) -> None:
        """Parse -> write -> parse keeps the entry count identical."""
        original = self._entries(api, oid_integration_fixture)
        assert original, "no entries in original parse"

        roundtrip = self._roundtrip(api, original)

        tm.that(len(roundtrip), eq=len(original))

    def test_roundtrip_preserves_dns_exactly(
        self, api: p.Ldif.Client, oid_integration_fixture: str
    ) -> None:
        """Every DN is preserved byte-for-byte across a round-trip."""
        original = self._entries(api, oid_integration_fixture)
        original_dns = sorted(entry.dn_str for entry in original)

        roundtrip_dns = sorted(entry.dn_str for entry in self._roundtrip(api, original))

        tm.that(roundtrip_dns, eq=original_dns)

    @pytest.mark.parametrize(
        "acl_attribute",
        ["orclaci", "orclentrylevelaci"],
        ids=["acl", "entry-level-acl"],
    )
    def test_roundtrip_preserves_oracle_acl_value_counts(
        self, api: p.Ldif.Client, oid_integration_fixture: str, acl_attribute: str
    ) -> None:
        """Total Oracle ACL value counts are invariant across a round-trip."""
        original = self._entries(api, oid_integration_fixture)
        original_count = sum(
            self._attribute_value_count(entry, acl_attribute) for entry in original
        )
        assert original_count > 0, (
            f"fixture must contain {acl_attribute} values to be meaningful"
        )

        roundtrip_count = sum(
            self._attribute_value_count(entry, acl_attribute)
            for entry in self._roundtrip(api, original)
        )

        tm.that(roundtrip_count, eq=original_count)


__all__: list[str] = ["TestsFlextLdifOidIntegration"]
