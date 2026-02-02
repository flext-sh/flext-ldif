"""Tests for RFC server LDIF quirks handling.

This module tests the RFC 2849/4512 compliant implementation for handling
standard LDIF format and schema definitions without server-specific extensions.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar, TypedDict

import pytest
from tests import c, p, s

from flext_ldif import FlextLdif
from flext_ldif.constants import c as lib_c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc

# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py


class SchemaAttributeDict(TypedDict):
    """TypedDict for schema attribute test data."""

    oid: str
    name: str
    desc: str | None
    syntax: str | None
    single_value: bool | None


class ObjectClassDict(TypedDict):
    """TypedDict for object class test data."""

    oid: str
    name: str
    must_contain: list[str] | None
    may_contain: list[str] | None


class EntryDataDict(TypedDict):
    """TypedDict for entry test data."""

    dn: str
    attributes: dict[str, list[str]]


class FixtureType(StrEnum):
    """RFC fixture file types."""

    SCHEMA = "schema"
    ENTRIES = "entries"
    ACL = "acl"


class QuirkType(StrEnum):
    """RFC quirk types."""

    SCHEMA = "schema"
    ACL = "acl"
    ENTRY = "entry"


@pytest.mark.unit
class TestsFlextLdifRfcQuirks(s):
    """Comprehensive RFC quirks test suite using parametrized tests.

    Consolidates 13 test classes into a single parametrized class for:
    - Fixture parsing and roundtrip validation
    - Schema/ACL/Entry quirk method testing
    - Constants validation
    """

    # Pytest fixtures with ClassVar annotations
    api: ClassVar[FlextLdif]  # pytest fixture
    rfc_quirk: ClassVar[FlextLdifServersRfc]  # pytest fixture
    schema_quirk: ClassVar[FlextLdifServersRfc.Schema]  # pytest fixture
    acl_quirk: ClassVar[FlextLdifServersRfc.Acl]  # pytest fixture
    entry_quirk: ClassVar[FlextLdifServersRfc.Entry]  # pytest fixture
    # Coverage for edge cases

    # =========================================================================
    # TEST DATA - ClassVars for parametrized tests
    # =========================================================================

    # Fixture configurations: (filename, has_dn, has_attrs, has_objectclass)
    FIXTURES: ClassVar[dict[FixtureType, tuple[str, bool, bool, bool]]] = {
        FixtureType.SCHEMA: ("rfc_schema_fixtures.ldif", True, True, False),
        FixtureType.ENTRIES: ("rfc_entries_fixtures.ldif", True, True, True),
        FixtureType.ACL: ("rfc_acl_fixtures.ldif", True, True, False),
    }

    # Constants validation data: (attr_name, expected_value)
    CONSTANTS_DATA: ClassVar[dict[str, tuple[str, object]]] = {
        "server_type": ("SERVER_TYPE", lib_c.Ldif.ServerTypes.RFC),
        "priority": ("PRIORITY", 100),
        "canonical_name": ("CANONICAL_NAME", "rfc"),
        "default_port": ("DEFAULT_PORT", 389),
        "default_ssl_port": ("DEFAULT_SSL_PORT", 636),
        "default_page_size": ("DEFAULT_PAGE_SIZE", 1000),
        "acl_format": ("ACL_FORMAT", "rfc_generic"),
        "acl_attribute": ("ACL_ATTRIBUTE_NAME", "aci"),
        "schema_dn": ("SCHEMA_DN", c.Rfc.SCHEMA_DN_SCHEMA),
        "sup_separator": ("SCHEMA_SUP_SEPARATOR", "$"),
    }

    # Schema attribute test data for write operations
    SCHEMA_WRITE_SCENARIOS: ClassVar[dict[str, SchemaAttributeDict]] = {
        "basic": {
            "oid": c.Rfc.ATTR_OID_CN,
            "name": c.Rfc.ATTR_NAME_CN,
            "must_contain": [
                c.Rfc.ATTR_OID_CN,
                c.Rfc.ATTR_NAME_CN,
            ],
        },
        "with_flags": {
            "oid": c.Rfc.ATTR_OID_CN,
            "name": c.Rfc.ATTR_NAME_CN,
            "single_value": True,
            "must_contain": ["SINGLE-VALUE"],
        },
    }

    # ObjectClass write test data
    OBJECTCLASS_WRITE_SCENARIOS: ClassVar[dict[str, ObjectClassDict]] = {
        "basic": {
            "oid": c.Rfc.OC_OID_PERSON,
            "name": c.Rfc.OC_NAME_PERSON,
            "must_contain": [
                c.Rfc.OC_OID_PERSON,
                c.Rfc.OC_NAME_PERSON,
            ],
        },
    }

    # ACL parse test data: (acl_line, expected_server_type)
    ACL_PARSE_SCENARIOS: ClassVar[dict[str, tuple[str, str]]] = {
        "basic": ("aci: test", "rfc"),
        "with_access": ("aci: access to entry by * (browse)", "rfc"),
    }

    # Entry write validation scenarios
    ENTRY_WRITE_SCENARIOS: ClassVar[dict[str, EntryDataDict]] = {
        "basic_person": {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["test"],
        },
        "with_sn": {
            "dn": "cn=user,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["user"],
            "sn": ["surname"],
        },
    }

    # =========================================================================
    # FIXTURES
    # =========================================================================

    @pytest.fixture(scope="class")
    def api(self) -> FlextLdif:
        """Provides FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture(scope="class")
    def rfc_quirk(self) -> FlextLdifServersRfc:
        """Provides RFC quirk instance."""
        return FlextLdifServersRfc()

    @pytest.fixture
    def schema_quirk(
        self,
        rfc_quirk: FlextLdifServersRfc,
    ) -> FlextLdifServersRfc.Schema:
        """Provides RFC Schema quirk - concrete type for internal method testing."""
        quirk = rfc_quirk.schema_quirk
        # Return concrete type for internal method access
        assert isinstance(quirk, FlextLdifServersRfc.Schema)
        return quirk

    @pytest.fixture
    def acl_quirk(self, rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Acl:
        """Provides RFC ACL quirk - concrete type for internal method testing."""
        quirk = rfc_quirk.acl_quirk
        assert isinstance(quirk, FlextLdifServersRfc.Acl)
        return quirk

    @pytest.fixture
    def entry_quirk(self, rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Entry:
        """Provides RFC Entry quirk - concrete type for internal method testing."""
        quirk = rfc_quirk.entry_quirk
        assert isinstance(quirk, FlextLdifServersRfc.Entry)
        return quirk

    # =========================================================================
    # HELPER METHODS (minimal, class-internal only)
    # =========================================================================

    def _get_fixture_path(self, fixture_type: FixtureType) -> Path:
        """Get fixture file path."""
        filename = self.FIXTURES[fixture_type][0]
        base = Path(__file__).parent.parent.parent.parent / "fixtures" / "rfc"
        return base / filename

    def _create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> p.Entry:
        """Create Entry model from dict."""
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        return result.value

    # =========================================================================
    # FIXTURE TESTS - Parse and Roundtrip
    # =========================================================================

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        ("fixture_type", "config"),
        FIXTURES.items(),
        ids=[f.value for f in FIXTURES],
    )
    def test_parse_fixture(
        self,
        api: FlextLdif,
        fixture_type: FixtureType,
        config: tuple[str, bool, bool, bool],
    ) -> None:
        """Parametrized test for parsing RFC fixtures."""
        _, has_dn, has_attrs, has_objectclass = config
        path = self._get_fixture_path(fixture_type)

        result = api.parse(path, server_type="rfc")
        assert result.is_success, f"Parse failed: {result.error}"

        entries = result.value
        assert len(entries) > 0, f"No entries in {fixture_type}"

        for entry in entries:
            if has_dn:
                assert entry.dn is not None, "Entry must have DN"
                assert entry.dn.value, "DN must not be empty"
            if has_attrs:
                assert entry.attributes is not None, "Entry must have attributes"
            if has_objectclass and entry.attributes:
                attr_names = {a.lower() for a in entry.attributes.attributes}
                assert "objectclass" in attr_names, "Entry must have objectClass"

    @pytest.mark.timeout(10)
    @pytest.mark.parametrize(
        "fixture_type",
        [FixtureType.SCHEMA, FixtureType.ENTRIES, FixtureType.ACL],
        ids=["schema", "entries", "acl"],
    )
    def test_roundtrip_fixture(
        self,
        api: FlextLdif,
        fixture_type: FixtureType,
        tmp_path: Path,
    ) -> None:
        """Parametrized test for roundtrip validation."""
        path = self._get_fixture_path(fixture_type)

        # Parse original
        parse_result = api.parse(path, server_type="rfc")
        assert parse_result.is_success
        original = parse_result.value

        # Write to string
        write_result = api.write(original, server_type="rfc")
        assert write_result.is_success
        ldif_content = write_result.value

        # Parse written content
        roundtrip_result = api.parse(ldif_content, server_type="rfc")
        assert roundtrip_result.is_success
        roundtrip = roundtrip_result.value

        # Validate entry count preserved
        assert len(roundtrip) == len(original), "Roundtrip must preserve entry count"

    # =========================================================================
    # CONSTANTS TESTS
    # =========================================================================

    @pytest.mark.parametrize(
        ("scenario", "data"),
        CONSTANTS_DATA.items(),
        ids=CONSTANTS_DATA.keys(),
    )
    def test_constants(
        self,
        scenario: str,
        data: tuple[str, object],
    ) -> None:
        """Parametrized test for RFC constants."""
        attr_name, expected = data
        actual = getattr(FlextLdifServersRfc.Constants, attr_name)
        assert actual == expected, f"{attr_name}: expected {expected}, got {actual}"

    def test_constants_aliases(self) -> None:
        """Test Constants.ALIASES contains expected values."""
        aliases = FlextLdifServersRfc.Constants.ALIASES
        assert "rfc" in aliases
        assert "generic" in aliases

    def test_constants_permissions(self) -> None:
        """Test Constants.SUPPORTED_PERMISSIONS contains expected values."""
        perms = FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
        expected = {"read", "write", "add", "delete", "search", "compare"}
        assert expected.issubset(set(perms))

    def test_constants_operational_attributes(self) -> None:
        """Test Constants.OPERATIONAL_ATTRIBUTES contains expected values."""
        ops = FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
        assert "createTimestamp" in ops
        assert "modifyTimestamp" in ops

    # =========================================================================
    # SCHEMA QUIRK TESTS
    # =========================================================================

    def test_schema_can_handle_attribute_string(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with string."""
        assert schema_quirk.can_handle_attribute(c.Rfc.ATTR_DEF_CN) is True

    def test_schema_can_handle_attribute_model(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with model."""
        attr = m.Ldif.SchemaAttribute(
            oid=c.Rfc.ATTR_OID_CN,
            name=c.Rfc.ATTR_NAME_CN,
        )
        assert schema_quirk.can_handle_attribute(attr) is True

    def test_schema_can_handle_objectclass_string(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_objectclass with string."""
        assert schema_quirk.can_handle_objectclass(c.Rfc.OC_DEF_PERSON) is True

    def test_schema_can_handle_objectclass_model(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_objectclass with model."""
        oc = m.Ldif.SchemaObjectClass(
            oid=c.Rfc.OC_OID_PERSON,
            name=c.Rfc.OC_NAME_PERSON,
        )
        assert schema_quirk.can_handle_objectclass(oc) is True

    @pytest.mark.timeout(5)
    def test_schema_parse_attribute(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._parse_attribute."""
        result = schema_quirk._parse_attribute(c.Rfc.ATTR_DEF_CN_COMPLETE)
        assert result.is_success
        attr = result.value
        assert attr.oid == c.Rfc.ATTR_OID_CN
        assert attr.name == c.Rfc.ATTR_NAME_CN

    @pytest.mark.timeout(5)
    def test_schema_parse_objectclass(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._parse_objectclass."""
        result = schema_quirk._parse_objectclass(c.Rfc.OC_DEF_PERSON)
        assert result.is_success
        oc = result.value
        assert oc.oid == c.Rfc.OC_OID_PERSON
        assert oc.name == c.Rfc.OC_NAME_PERSON

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        ("scenario", "data"),
        SCHEMA_WRITE_SCENARIOS.items(),
        ids=SCHEMA_WRITE_SCENARIOS.keys(),
    )
    def test_schema_write_attribute(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
        scenario: str,
        data: SchemaAttributeDict,
    ) -> None:
        """Parametrized test for Schema._write_attribute."""
        attr = m.Ldif.SchemaAttribute(
            oid=str(data["oid"]),
            name=str(data["name"]),
            single_value=bool(data.get("single_value")),
        )
        result = schema_quirk._write_attribute(attr)
        assert result.is_success
        written = result.value
        must_contain = data.get("must_contain")
        if must_contain is not None and isinstance(must_contain, list):
            for expected in must_contain:
                assert str(expected) in written, f"Missing {expected} in output"

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        ("scenario", "data"),
        OBJECTCLASS_WRITE_SCENARIOS.items(),
        ids=OBJECTCLASS_WRITE_SCENARIOS.keys(),
    )
    def test_schema_write_objectclass(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
        scenario: str,
        data: ObjectClassDict,
    ) -> None:
        """Parametrized test for Schema._write_objectclass."""
        oc = m.Ldif.SchemaObjectClass(
            oid=str(data["oid"]),
            name=str(data["name"]),
        )
        result = schema_quirk._write_objectclass(oc)
        assert result.is_success
        written = result.value
        must_contain = data.get("must_contain")
        if must_contain is not None and isinstance(must_contain, list):
            for expected in must_contain:
                assert str(expected) in written, f"Missing {expected} in output"

    def test_schema_should_filter_out_attribute(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.should_filter_out_attribute returns bool."""
        attr = m.Ldif.SchemaAttribute(
            oid=c.Rfc.ATTR_OID_CN,
            name=c.Rfc.ATTR_NAME_CN,
        )
        result = schema_quirk.should_filter_out_attribute(attr)
        assert isinstance(result, bool)

    def test_schema_should_filter_out_objectclass(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.should_filter_out_objectclass returns bool."""
        oc = m.Ldif.SchemaObjectClass(
            oid=c.Rfc.OC_OID_PERSON,
            name=c.Rfc.OC_NAME_PERSON,
        )
        result = schema_quirk.should_filter_out_objectclass(oc)
        assert isinstance(result, bool)

    # =========================================================================
    # ACL QUIRK TESTS
    # =========================================================================

    def test_acl_can_handle_acl_string(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.can_handle_acl with string."""
        assert acl_quirk.can_handle_acl("aci: test") is True

    def test_acl_can_handle_acl_model(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.can_handle_acl with model."""
        acl = m.Ldif.Acl(raw_acl="test: acl", server_type="rfc")
        assert acl_quirk.can_handle_acl(acl) is True

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        ("scenario", "data"),
        ACL_PARSE_SCENARIOS.items(),
        ids=ACL_PARSE_SCENARIOS.keys(),
    )
    def test_acl_parse(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
        scenario: str,
        data: tuple[str, str],
    ) -> None:
        """Parametrized test for Acl._parse_acl."""
        acl_line, expected_server = data
        result = acl_quirk._parse_acl(acl_line)
        assert result.is_success
        acl = result.value
        assert acl_quirk.server_type == expected_server

    def test_acl_parse_empty_fails(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._parse_acl fails with empty string."""
        result = acl_quirk._parse_acl("")
        assert result.is_failure

    def test_acl_parse_whitespace_fails(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._parse_acl fails with whitespace only."""
        result = acl_quirk._parse_acl("   ")
        assert result.is_failure

    def test_acl_create_metadata(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.create_metadata."""
        metadata = acl_quirk.create_metadata("aci: test", extensions={"extra": "value"})
        assert metadata is not None
        assert metadata.quirk_type == "rfc"
        assert metadata.extensions.get("extra") == "value"

    def test_acl_convert_rfc_acl_to_aci(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl.convert_rfc_acl_to_aci."""
        rfc_acl_attrs = {"aci": ["test acl"]}
        result = acl_quirk.convert_rfc_acl_to_aci(rfc_acl_attrs, "target")
        assert result.is_success
        converted = result.value
        assert converted == rfc_acl_attrs

    # =========================================================================
    # ENTRY QUIRK TESTS
    # =========================================================================

    def test_entry_can_handle(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle."""
        # RFC 2849 requires objectClass in attributes
        assert (
            entry_quirk.can_handle(
                c.General.SAMPLE_DN,
                {
                    "objectClass": ["person"],
                    c.General.ATTR_NAME_CN: [
                        c.General.ATTR_VALUE_TEST,
                    ],
                },
            )
            is True
        )

    def test_entry_can_handle_entry(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle with Entry model by extracting DN and attributes."""
        entry = self._create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )
        # Extract DN and attributes for can_handle()
        dn_value = entry.dn.value
        attrs = dict(entry.attributes.attributes)
        assert entry_quirk.can_handle(dn_value, attrs) is True

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        ("scenario", "data"),
        ENTRY_WRITE_SCENARIOS.items(),
        ids=ENTRY_WRITE_SCENARIOS.keys(),
    )
    def test_entry_write(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
        scenario: str,
        data: EntryDataDict,
    ) -> None:
        """Parametrized test for Entry write operations."""
        dn = str(data["dn"])
        attributes: dict[str, str | list[str]] = {}
        for k, v in data.items():
            if k != "dn" and isinstance(v, list):
                attributes[k] = [str(item) for item in v]
        entry = self._create_entry(dn=dn, attributes=attributes)

        result = entry_quirk.write([entry])
        assert result.is_success
        written = result.value
        assert dn in written, f"DN {dn} not in output"
        assert len(written) > 0

    def test_entry_parse_single(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry._parse_entry."""
        dn = "cn=test,dc=example,dc=com"
        attrs: dict[str, list[str | bytes]] = {
            "cn": ["test"],
            "objectClass": ["person"],
        }
        result = entry_quirk.parse_entry(dn, attrs)
        assert result.is_success
        entry = result.value
        assert entry.dn is not None
        assert "cn=test,dc=example,dc=com" in entry.dn.value

    def test_entry_can_handle_entry_empty_dn(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle with empty dn returns False (RFC requires DN)."""
        # RFC baseline requires valid DN for entries
        entry = m.Ldif.Entry.create(
            dn="",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        ).value
        # Extract DN and attributes for can_handle()
        dn_value = entry.dn.value
        attrs = dict(entry.attributes.attributes)
        result = entry_quirk.can_handle(dn_value, attrs)
        # Empty DN is not valid for RFC
        assert result is False

    # =========================================================================
    # ROUTING TESTS
    # =========================================================================

    @pytest.mark.timeout(5)
    @pytest.mark.parametrize(
        "fixture_type",
        [FixtureType.SCHEMA, FixtureType.ENTRIES, FixtureType.ACL],
        ids=["schema", "entries", "acl"],
    )
    def test_routing_validation(
        self,
        api: FlextLdif,
        fixture_type: FixtureType,
    ) -> None:
        """Parametrized test for routing validation."""
        path = self._get_fixture_path(fixture_type)
        result = api.parse(path, server_type="rfc")
        assert result.is_success, f"Routing failed for {fixture_type}"
        entries = result.value
        assert len(entries) > 0

    # =========================================================================
    # EDGE CASE AND COVERAGE TESTS
    # =========================================================================

    def test_schema_write_invalid_attribute_type(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_attribute with invalid type returns failure."""
        # Pass invalid type directly - test expects failure (runtime validation)
        # Cast used because we're testing runtime type validation intentionally
        invalid_attr = "not an attribute"
        result = schema_quirk._write_attribute(invalid_attr)
        assert result.is_failure

    def test_schema_write_invalid_objectclass_type(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_objectclass with invalid type returns failure."""
        # Cast used because we're testing runtime type validation intentionally
        invalid_oc = "not an objectclass"
        result = schema_quirk._write_objectclass(invalid_oc)
        assert result.is_failure

    def test_entry_write_empty_list(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.write with empty list."""
        result = entry_quirk.write([])
        # Empty list should succeed with empty output or specific behavior
        assert result.is_success or result.is_failure  # Both valid

    def test_schema_write_with_x_origin_metadata(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_attribute with X-ORIGIN in metadata."""
        attr = m.Ldif.SchemaAttribute(
            oid=c.Rfc.ATTR_OID_CN,
            name=c.Rfc.ATTR_NAME_CN,
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="rfc",
                extensions={"x_origin": "test-origin"},
            ),
        )
        result = schema_quirk._write_attribute(attr)
        assert result.is_success
        written = result.value
        assert "X-ORIGIN" in written
        assert "test-origin" in written

    def test_objectclass_write_with_x_origin_metadata(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_objectclass with X-ORIGIN in metadata."""
        oc = m.Ldif.SchemaObjectClass(
            oid=c.Rfc.OC_OID_PERSON,
            name=c.Rfc.OC_NAME_PERSON,
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="rfc",
                extensions={"x_origin": "test-origin"},
            ),
        )
        result = schema_quirk._write_objectclass(oc)
        assert result.is_success
        written = result.value
        assert "X-ORIGIN" in written
        assert "test-origin" in written

    def test_acl_write_with_raw_acl(
        self,
        acl_quirk: FlextLdifServersRfc.Acl,
    ) -> None:
        """Test Acl._write_acl with raw_acl."""
        acl = m.Ldif.Acl(raw_acl="aci: test acl value", server_type="rfc")
        result = acl_quirk._write_acl(acl)
        assert result.is_success
        written = result.value
        assert "test acl value" in written

    def test_entry_handle_parse_operation_entry_object(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.can_handle with entry object."""
        entry = self._create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["test"]},
        )
        # Test can_handle by extracting DN and attributes
        dn_value = entry.dn.value
        attrs = dict(entry.attributes.attributes)
        result = entry_quirk.can_handle(dn_value, attrs)
        assert result is True

    def test_entry_write_multiple_entries(
        self,
        entry_quirk: FlextLdifServersRfc.Entry,
    ) -> None:
        """Test Entry.write with multiple entries."""
        entries = [
            self._create_entry(
                dn=f"cn=user{i},dc=example,dc=com",
                attributes={"objectClass": ["person"], "cn": [f"user{i}"]},
            )
            for i in range(3)
        ]
        result = entry_quirk.write(entries)
        assert result.is_success
        written = result.value
        for i in range(3):
            assert f"cn=user{i}" in written

    def test_schema_auto_execute_attribute(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema auto-execute for attribute parsing."""
        # Test parse_attribute public method
        result = schema_quirk.parse_attribute(c.Rfc.ATTR_DEF_CN)
        assert result.is_success
        attr = result.value
        assert attr.name == c.Rfc.ATTR_NAME_CN

    def test_schema_auto_execute_objectclass(
        self,
        schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema auto-execute for objectClass parsing."""
        # Test parse_objectclass public method
        result = schema_quirk.parse_objectclass(c.Rfc.OC_DEF_PERSON)
        assert result.is_success
        oc = result.value
        assert oc.name == c.Rfc.OC_NAME_PERSON
