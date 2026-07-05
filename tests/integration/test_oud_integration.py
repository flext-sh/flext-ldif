"""Behavioral integration tests for OUD (Oracle Unified Directory) fixtures.

Exercises the public ``ldif`` client contract end-to-end against real OUD
fixture data:

- Parsing OUD schema / ACL / entry / integration fixtures returns a successful
  ``r[ParseResponse]`` exposing entries through the public model API.
- Oracle-specific schema definitions and objectClasses survive parsing and are
  observable via ``entry.attributes`` public accessors.
- Parse -> write -> parse round-trips preserve entry count, DN set, and ACI
  values (observable contract, never internal structures).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest

from tests.utilities import TestsFlextLdifUtilities as u

if TYPE_CHECKING:
    from tests.models import m
    from tests.protocols import p


class TestsFlextLdifOudIntegration:
    """Behavioral contract tests for parsing and round-tripping OUD LDIF.

    All fixtures (``api``, ``oud_schema_fixture``, ``oud_acl_fixture``,
    ``oud_entries_fixture``, ``oud_integration_fixture``) are provided by the
    shared ``tests.unit.fixtures`` pytest plugin.
    """

    ORACLE_ENTERPRISE_OID_PREFIX: ClassVar[str] = "2.16.840.1.113894"
    ORACLE_OBJECTCLASS_MARKERS: ClassVar[tuple[str, ...]] = (
        "orclcontext",
        "orclcontainer",
        "orclprivilegegroup",
    )
    MIN_ENTRY_FIXTURE_COUNT: ClassVar[int] = 10

    @staticmethod
    def _attrs(entry: m.Ldif.Entry) -> m.Ldif.Attributes:
        """Return an entry's attributes, asserting the public field is present."""
        attributes = entry.attributes
        assert attributes is not None, "Parsed entry must expose attributes"
        return attributes

    @staticmethod
    def _dn_value(entry: m.Ldif.Entry) -> str:
        """Return an entry's DN string via the public DN model."""
        dn = entry.dn
        assert dn is not None, "Parsed entry must expose a DN"
        return dn.value

    @classmethod
    def _object_classes(cls, entry: m.Ldif.Entry) -> list[str]:
        """Return an entry's objectClass values via the public accessor."""
        attributes = cls._attrs(entry)
        values = attributes.get("objectClass") or attributes.get("objectclass")
        return list(values) if values else []

    # --- Schema fixture ---------------------------------------------------

    def test_parse_schema_fixture_returns_success_with_single_entry(
        self,
        api: p.Ldif.LdifClient,
        oud_schema_fixture: str,
    ) -> None:
        """Parsing the OUD schema fixture yields exactly one schema entry."""
        response = u.Tests.assert_success(
            api.parse_ldif(oud_schema_fixture),
            error_msg="OUD schema parsing must succeed",
        )

        assert len(response.entries) == 1

    def test_schema_entry_exposes_oracle_attribute_definitions(
        self,
        api: p.Ldif.LdifClient,
        oud_schema_fixture: str,
    ) -> None:
        """The schema entry carries Oracle-namespaced attributeType definitions."""
        response = u.Tests.assert_success(api.parse_ldif(oud_schema_fixture))
        schema_entry = response.entries[0]

        attribute_types = self._attrs(schema_entry).get("attributeTypes") or []

        assert attribute_types, "Schema entry must expose attributeTypes"
        assert any(
            self.ORACLE_ENTERPRISE_OID_PREFIX in definition
            for definition in attribute_types
        ), "Expected at least one Oracle-namespaced attributeType"

    def test_schema_entry_exposes_oracle_object_class_definitions(
        self,
        api: p.Ldif.LdifClient,
        oud_schema_fixture: str,
    ) -> None:
        """The schema entry carries Oracle-namespaced objectClass definitions."""
        response = u.Tests.assert_success(api.parse_ldif(oud_schema_fixture))
        schema_entry = response.entries[0]

        object_classes = self._attrs(schema_entry).get("objectClasses") or []

        assert object_classes, "Schema entry must expose objectClasses"
        assert any(
            self.ORACLE_ENTERPRISE_OID_PREFIX in definition
            for definition in object_classes
        ), "Expected at least one Oracle-namespaced objectClass"

    # --- ACL fixture ------------------------------------------------------

    def test_parse_acl_fixture_yields_entries_all_carrying_aci(
        self,
        api: p.Ldif.LdifClient,
        oud_acl_fixture: str,
    ) -> None:
        """Every entry in the ACL fixture exposes an ``aci`` attribute."""
        response = u.Tests.assert_success(
            api.parse_ldif(oud_acl_fixture),
            error_msg="OUD ACL parsing must succeed",
        )

        assert response.entries, "ACL fixture must produce entries"
        assert all(
            self._attrs(entry).has_attribute("aci") for entry in response.entries
        ), "Every ACL fixture entry must carry an aci attribute"

    def test_aci_values_survive_write_then_reparse(
        self,
        api: p.Ldif.LdifClient,
        oud_acl_fixture: str,
    ) -> None:
        """ACI values are preserved through a parse -> write -> parse round-trip."""
        original = u.Tests.assert_success(api.parse_ldif(oud_acl_fixture))
        original_acis = {
            self._dn_value(entry): sorted(self._attrs(entry).get("aci") or [])
            for entry in original.entries
        }

        written = u.Tests.assert_success(
            api.write(original.entries),
            error_msg="Writing ACL entries must succeed",
        )
        written_content = written.content
        assert written_content is not None, "Write must produce LDIF content"
        reparsed = u.Tests.assert_success(api.parse_ldif(written_content))

        roundtrip_acis = {
            self._dn_value(entry): sorted(self._attrs(entry).get("aci") or [])
            for entry in reparsed.entries
        }

        assert roundtrip_acis == original_acis

    # --- Entry fixture ----------------------------------------------------

    def test_parse_entries_fixture_meets_minimum_count(
        self,
        api: p.Ldif.LdifClient,
        oud_entries_fixture: str,
    ) -> None:
        """The entries fixture parses into at least the expected number of entries."""
        response = u.Tests.assert_success(
            api.parse_ldif(oud_entries_fixture),
            error_msg="OUD entries parsing must succeed",
        )

        assert len(response.entries) >= self.MIN_ENTRY_FIXTURE_COUNT

    def test_oracle_object_classes_preserved_through_parsing(
        self,
        api: p.Ldif.LdifClient,
        oud_entries_fixture: str,
    ) -> None:
        """Oracle objectClasses (orclContext, ...) survive parsing intact."""
        response = u.Tests.assert_success(api.parse_ldif(oud_entries_fixture))

        entries_with_oracle_oc = sum(
            1
            for entry in response.entries
            if any(
                marker in object_class.lower()
                for object_class in self._object_classes(entry)
                for marker in self.ORACLE_OBJECTCLASS_MARKERS
            )
        )

        assert entries_with_oracle_oc > 0, (
            "Expected entries carrying Oracle objectClasses"
        )

    # --- Round-trip integrity --------------------------------------------

    def test_roundtrip_preserves_entry_count_and_dn_set(
        self,
        api: p.Ldif.LdifClient,
        oud_integration_fixture: str,
    ) -> None:
        """Parse -> write -> parse preserves entry count and the exact DN set."""
        first = u.Tests.assert_success(
            api.parse_ldif(oud_integration_fixture),
            error_msg="Initial parse must succeed",
        )
        assert first.entries, "Fixture must produce entries"

        written = u.Tests.assert_success(
            api.write(first.entries),
            error_msg="Write must succeed",
        )
        written_content = written.content
        assert written_content, "Write must produce non-empty LDIF"

        second = u.Tests.assert_success(
            api.parse_ldif(written_content),
            error_msg="Re-parse must succeed",
        )

        assert len(second.entries) == len(first.entries)
        assert {self._dn_value(entry) for entry in second.entries} == {
            self._dn_value(entry) for entry in first.entries
        }

    def test_roundtrip_is_idempotent_on_dn_set(
        self,
        api: p.Ldif.LdifClient,
        oud_integration_fixture: str,
    ) -> None:
        """Parsing the same fixture twice yields an identical DN set (invariant)."""
        first = u.Tests.assert_success(api.parse_ldif(oud_integration_fixture))
        second = u.Tests.assert_success(api.parse_ldif(oud_integration_fixture))

        assert {self._dn_value(entry) for entry in first.entries} == {
            self._dn_value(entry) for entry in second.entries
        }

    @pytest.mark.parametrize(
        "dn_with_spaces",
        [
            "cn=Oracle Context, dc=example, dc=com",
            "uid=jdoe, ou=People, dc=example, dc=com",
        ],
    )
    def test_roundtrip_preserves_dn_rdn_components_with_spaces(
        self,
        api: p.Ldif.LdifClient,
        dn_with_spaces: str,
    ) -> None:
        """DNs whose RDNs are separated by ', ' keep their component count."""
        source_ldif = (
            f"dn: {dn_with_spaces}\ncn: Oracle Context\nobjectClass: top\n"
        )
        parsed = u.Tests.assert_success(api.parse_ldif(source_ldif))
        assert len(parsed.entries) == 1
        original_dn = self._dn_value(parsed.entries[0])

        written = u.Tests.assert_success(api.write(parsed.entries))
        written_content = written.content
        assert written_content is not None, "Write must produce LDIF content"
        reparsed = u.Tests.assert_success(api.parse_ldif(written_content))

        assert len(reparsed.entries) == 1
        roundtrip_dn = self._dn_value(reparsed.entries[0])
        expected_rdn_count = original_dn.count("=")
        assert roundtrip_dn.count("=") == expected_rdn_count

    # --- Metadata contract ------------------------------------------------

    def test_parsed_entries_expose_public_dn_attributes_and_metadata(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A parsed entry exposes DN, attribute values, and metadata publicly."""
        source_ldif = (
            "dn: cn=OracleContext,dc=example,dc=com\n"
            "cn: OracleContext\n"
            "objectClass: top\n"
            "objectClass: orclContext\n"
            "orclVersion: 90600\n"
        )

        response = u.Tests.assert_success(api.parse_ldif(source_ldif))

        assert len(response.entries) == 1
        entry = response.entries[0]
        attributes = self._attrs(entry)
        assert self._dn_value(entry) == "cn=OracleContext,dc=example,dc=com"
        assert attributes.get("orclVersion") == ["90600"]
        assert attributes.get("objectClass") == ["top", "orclContext"]
        assert entry.metadata is not None


__all__: list[str] = ["TestsFlextLdifOudIntegration"]
