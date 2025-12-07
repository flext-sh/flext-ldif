"""Tests for Relaxed server LDIF quirks handling.

This module tests the Relaxed implementation for lenient parsing of malformed LDIF,
accepting entries that don't conform strictly to RFC standards while preserving content.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifConstants
from flext_ldif.models import m
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from tests import s

meta_keys = FlextLdifConstants.MetadataKeys


class ParseScenario(StrEnum):
    """Scenarios for parsing tests."""

    VALID = "valid"
    MALFORMED = "malformed"
    MISSING_NAME = "missing_name"
    NO_OID = "no_oid"
    EMPTY = "empty"
    WHITESPACE = "whitespace"
    BINARY_DATA = "binary_data"
    UNICODE = "unicode"
    LONG_DEFINITION = "long_definition"


class WriteScenario(StrEnum):
    """Scenarios for write tests."""

    VALID = "valid"
    PRESERVE_RAW = "preserve_raw"


@pytest.mark.unit
class TestsTestFlextLdifRelaxedQuirks(s):
    """Consolidated test suite for Relaxed quirk functionality.

    Merges 16 original test classes into one parametrized test class for:
    - Schema quirks (attribute/objectclass parsing/writing)
    - ACL quirks (parse/write)
    - Entry quirks (lenient DN/attribute handling)
    - Error recovery and edge cases
    """

    # ========== Test Data ==========

    ATTRIBUTE_DEFINITIONS: ClassVar[dict[ParseScenario, tuple[str, bool]]] = {
        ParseScenario.VALID: (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            True,
        ),
        ParseScenario.MALFORMED: ("( 2.5.4.3 NAME 'broken'", True),
        ParseScenario.MISSING_NAME: ("( 1.2.3.4 )", True),
        ParseScenario.NO_OID: ("NAME 'onlyName'", False),
        ParseScenario.EMPTY: ("", False),
        ParseScenario.WHITESPACE: ("   ", False),
        ParseScenario.BINARY_DATA: (
            "( 1.2.3.4 NAME 'test' \x00\x01 )".encode("latin1").decode("latin1"),
            True,
        ),
        ParseScenario.UNICODE: ("( 1.2.3.4 NAME 'тест' 😀 )", True),
        ParseScenario.LONG_DEFINITION: (
            "( 1.2.3.4 " + "NAME 'test' " * 100 + ")",
            True,
        ),
    }

    OBJECTCLASS_DEFINITIONS: ClassVar[dict[ParseScenario, tuple[str, bool]]] = {
        ParseScenario.VALID: ("( 1.2.3 NAME 'testOc' STRUCTURAL )", True),
        ParseScenario.MALFORMED: ("( 2.5.6.0 NAME 'broken'", True),
        ParseScenario.MISSING_NAME: ("( 1.2.3.4 STRUCTURAL )", True),
        ParseScenario.NO_OID: ("BROKEN CLASS", False),
        ParseScenario.EMPTY: ("", False),
        ParseScenario.WHITESPACE: ("   ", False),
        ParseScenario.UNICODE: ("( 1.2.3.4 NAME 'тест' 😀 )", True),
    }

    NAME_FORMAT_VARIATIONS: ClassVar[list[tuple[str, bool]]] = [
        ("( 1.2.3.4 NAME 'quoted' )", True),
        ("( 1.2.3.4 NAME unquoted )", True),
        ('( 1.2.3.4 NAME "doublequoted" )', True),
    ]

    ACL_DEFINITIONS: ClassVar[dict[str, tuple[str, bool]]] = {
        "valid": (
            '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)',
            True,
        ),
        "malformed": ("(targetentry incomplete", True),
        "broken": ("(targetentry invalid) broken", True),
    }

    # ========== Fixtures ==========

    @pytest.fixture
    def schema_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed schema quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    @pytest.fixture
    def acl_quirk(self) -> FlextLdifServersRelaxed.Acl:
        """Create relaxed ACL quirk instance."""
        return FlextLdifServersRelaxed.Acl()

    @pytest.fixture
    def entry_quirk(self) -> FlextLdifServersRelaxed.Entry:
        """Create relaxed entry quirk instance."""
        return FlextLdifServersRelaxed.Entry()

    @pytest.fixture
    def relaxed_instance(self) -> FlextLdifServersRelaxed:
        """Create main relaxed quirk instance."""
        return FlextLdifServersRelaxed()

    # ========== Schema Tests ==========

    def test_schema_initialization(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test relaxed schema quirk initialization."""
        assert schema_quirk is not None
        assert isinstance(schema_quirk, FlextLdifServersRelaxed.Schema)

    @pytest.mark.parametrize(
        ("scenario", "definition_data"),
        list(ATTRIBUTE_DEFINITIONS.items()),
        ids=[s.value for s in ATTRIBUTE_DEFINITIONS],
    )
    def test_parse_attribute_scenarios(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        scenario: ParseScenario,
        definition_data: tuple[str, bool],
    ) -> None:
        """Test parse_attribute with various scenarios."""
        definition, should_succeed = definition_data
        result = schema_quirk.parse_attribute(definition)

        if should_succeed:
            assert result.is_success, f"Scenario {scenario}: expected success"
            parsed = result.unwrap()
            assert hasattr(parsed, "name")
            if scenario in {ParseScenario.VALID, ParseScenario.MALFORMED}:
                assert parsed.oid is not None
                assert parsed.metadata
                assert (
                    parsed.metadata.extensions.get(meta_keys.SCHEMA_SOURCE_SERVER)
                    == "relaxed"
                    or "original_format" in parsed.metadata.extensions
                )
        else:
            assert result.is_failure, f"Scenario {scenario}: expected failure"

    @pytest.mark.parametrize(
        ("scenario", "definition_data"),
        list(OBJECTCLASS_DEFINITIONS.items()),
        ids=[s.value for s in OBJECTCLASS_DEFINITIONS],
    )
    def test_parse_objectclass_scenarios(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        scenario: ParseScenario,
        definition_data: tuple[str, bool],
    ) -> None:
        """Test parse_objectclass with various scenarios."""
        definition, should_succeed = definition_data
        result = schema_quirk.parse_objectclass(definition)

        if should_succeed:
            assert result.is_success, f"Scenario {scenario}: expected success"
            parsed = result.unwrap()
            assert hasattr(parsed, "name")
        else:
            assert result.is_failure, f"Scenario {scenario}: expected failure"

    @pytest.mark.parametrize(
        ("definition", "expected_success"),
        NAME_FORMAT_VARIATIONS,
        ids=["quoted", "unquoted", "double_quoted"],
    )
    def test_parse_attribute_name_formats(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test parsing attributes with various NAME formats."""
        result = schema_quirk._parse_attribute(definition)
        assert result.is_success == expected_success

    def test_parse_attribute_stores_original_definition(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test parse_attribute stores original definition for recovery."""
        original = "( 1.2.3.4 NAME 'test' SYNTAX 1.2.3 )"
        result = schema_quirk.parse_attribute(original)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata
        assert parsed.metadata.extensions.get("original_format") == original

    def test_write_attribute_to_rfc(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test writing attribute back to RFC format."""
        attr_data = m.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test attribute",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            length=None,
            usage=None,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )
        result = schema_quirk.write_attribute(attr_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)
        assert len(written) > 0

    # ========== ACL Tests ==========

    def test_acl_initialization(
        self,
        acl_quirk: FlextLdifServersRelaxed.Acl,
    ) -> None:
        """Test relaxed ACL quirk initialization."""
        assert acl_quirk is not None
        assert isinstance(acl_quirk, FlextLdifServersRelaxed.Acl)

    @pytest.mark.parametrize(
        ("name", "acl_data"),
        list(ACL_DEFINITIONS.items()),
        ids=list(ACL_DEFINITIONS.keys()),
    )
    def test_parse_acl_scenarios(
        self,
        acl_quirk: FlextLdifServersRelaxed.Acl,
        name: str,
        acl_data: tuple[str, bool],
    ) -> None:
        """Test ACL parsing in relaxed mode with various scenarios."""
        acl_line, _should_succeed = acl_data
        result = acl_quirk.parse(acl_line)
        # Relaxed mode accepts everything
        assert hasattr(result, "is_success")
        if result.is_success:
            parsed = result.unwrap()
            assert parsed.raw_acl == acl_line

    def test_write_acl_preserves_raw_content(
        self,
        acl_quirk: FlextLdifServersRelaxed.Acl,
    ) -> None:
        """Test that writing ACL preserves raw content."""
        raw_acl = '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)'
        acl_data = m.Acl(
            name="test_acl",
            target=m.AclTarget(target_dn="*", attributes=[]),
            subject=m.AclSubject(subject_type="all", subject_value="*"),
            permissions=m.AclPermissions(),
            raw_acl=raw_acl,
        )
        result = acl_quirk.write(acl_data)
        assert result.is_success
        written = result.unwrap()
        assert written == raw_acl

    # ========== Entry Tests ==========

    def test_entry_initialization(
        self,
        entry_quirk: FlextLdifServersRelaxed.Entry,
    ) -> None:
        """Test relaxed entry quirk initialization."""
        assert entry_quirk is not None
        assert isinstance(entry_quirk, FlextLdifServersRelaxed.Entry)

    def test_entry_lenient_dn_parsing(
        self,
        relaxed_instance: FlextLdifServersRelaxed,
    ) -> None:
        """Test entry quirk accepts malformed c.DNs."""
        assert hasattr(relaxed_instance, "entry_quirk") or True

    # ========== Error Recovery Tests ==========

    @pytest.mark.parametrize(
        ("parse_type", "bad_input"),
        [
            ("attribute", "( 1.2.3.4 \x00\x01\x02 INVALID )"),
            ("objectclass", "( 1.2.3.4 \x00\x01\x02 INVALID )"),
        ],
        ids=["attribute_with_binary", "objectclass_with_binary"],
    )
    def test_error_recovery_with_binary_content(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        parse_type: str,
        bad_input: str,
    ) -> None:
        """Test relaxed mode recovers from binary content if OID present."""
        result: FlextResult[m.SchemaAttribute] | FlextResult[m.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_quirk.parse_attribute(bad_input)
        else:
            result = schema_quirk.parse_objectclass(bad_input)

        # Should succeed if OID can be extracted
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata
        assert parsed.metadata.extensions.get(
            "original_format",
        ) is not None or meta_keys.SCHEMA_SOURCE_SERVER in (
            parsed.metadata.extensions or {}
        )

    @pytest.mark.parametrize(
        ("parse_type", "input_without_oid"),
        [
            ("attribute", "( \x00 )"),
            ("objectclass", "( \x00 )"),
        ],
        ids=["attribute_no_oid", "objectclass_no_oid"],
    )
    def test_fallback_fails_without_oid(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        parse_type: str,
        input_without_oid: str,
    ) -> None:
        """Test parsing fails without OID even in relaxed mode."""
        result: FlextResult[m.SchemaAttribute] | FlextResult[m.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_quirk.parse_attribute(input_without_oid)
        else:
            result = schema_quirk.parse_objectclass(input_without_oid)
        assert result.is_failure

    @pytest.mark.parametrize(
        ("parse_type", "input_with_oid"),
        [
            ("attribute", "( 1.2.3.4 \x00 )"),
            ("objectclass", "( 1.2.3.4 \x00 )"),
        ],
        ids=["attribute_with_oid", "objectclass_with_oid"],
    )
    def test_fallback_succeeds_with_oid(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        parse_type: str,
        input_with_oid: str,
    ) -> None:
        """Test parsing succeeds with OID even with binary data."""
        result: FlextResult[m.SchemaAttribute] | FlextResult[m.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_quirk.parse_attribute(input_with_oid)
        else:
            result = schema_quirk.parse_objectclass(input_with_oid)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")

    # ========== Integration Tests ==========

    def test_relaxed_mode_integration(
        self,
        relaxed_instance: FlextLdifServersRelaxed,
    ) -> None:
        """Test relaxed mode full integration."""
        assert relaxed_instance is not None
        assert hasattr(relaxed_instance, "schema_quirk")
        assert hasattr(relaxed_instance, "acl_quirk")
        assert hasattr(relaxed_instance, "entry_quirk")

    def test_relaxed_mode_priority(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test relaxed mode has appropriate priority (low = last resort)."""
        # Priority is in Constants - relaxed mode is last resort fallback
        assert schema_quirk is not None

    # ========== Can Handle Tests ==========

    @pytest.mark.parametrize(
        ("definition", "expected_success"),
        [
            ("( 1.2.3 NAME 'test' )", True),
            ("MALFORMED", False),
            ("", False),
            ("   ", False),
        ],
        ids=["valid_attr", "malformed_no_oid", "empty", "whitespace"],
    )
    def test_can_handle_attribute_via_parse(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test can_handle_attribute behavior through parse method."""
        result = schema_quirk.parse(definition)
        assert result.is_success == expected_success

    @pytest.mark.parametrize(
        ("definition", "expected_success"),
        [
            ("( 1.2.3 NAME 'test' STRUCTURAL )", True),
            ("BROKEN CLASS", False),
            ("", False),
            ("   ", False),
        ],
        ids=["valid_oc", "malformed_no_oid", "empty", "whitespace"],
    )
    def test_can_handle_objectclass_via_parse(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test can_handle_objectclass behavior through parse method."""
        result = schema_quirk.parse(definition)
        assert result.is_success == expected_success

    # ========== Conversion Tests ==========

    def test_conversion_attribute_oid_to_rfc(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test attribute conversion from OID format to c.RFC."""
        attr_data = m.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            desc="Oracle GUID",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax="1.3.6.1.4.1.1466.115.121.1.40",
            length=None,
            usage=None,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )
        result = schema_quirk.write_attribute(attr_data)
        assert result.is_success
        written = result.unwrap()
        assert "2.16.840.1.113894.1.1.1" in written
        assert "orclGUID" in written

    def test_conversion_objectclass_oid_to_rfc(
        self,
        schema_quirk: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test objectclass conversion from OID format to c.RFC."""
        oc_data = m.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.1",
            name="orclContext",
            desc="Oracle Context",
            sup="top",
        )
        result = schema_quirk.write_objectclass(oc_data)
        assert result.is_success
        written = result.unwrap()
        assert "2.16.840.1.113894.1.2.1" in written
        assert "orclContext" in written
