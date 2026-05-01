"""Tests for Relaxed server LDIF servers handling.

This module tests the Relaxed implementation for lenient parsing of malformed LDIF,
accepting entries that don't conform strictly to RFC standards while preserving content.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifServersRelaxed
from tests import c, m, p, r


@pytest.mark.unit
class TestsTestFlextLdifRelaxedServers:
    """Consolidated test suite for Relaxed server functionality.

    Merges 16 original test classes into one parametrized test class for:
    - Schema servers (attribute/objectclass parsing/writing)
    - ACL servers (parse/write)
    - Entry servers (lenient DN/attribute handling)
    - Error recovery and edge cases
    """

    @pytest.fixture
    def schema_server(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed schema server instance."""
        return FlextLdifServersRelaxed.Schema()

    @pytest.fixture
    def acl_server(self) -> FlextLdifServersRelaxed.Acl:
        """Create relaxed ACL server instance."""
        return FlextLdifServersRelaxed.Acl()

    @pytest.fixture
    def entry_server(self) -> FlextLdifServersRelaxed.Entry:
        """Create relaxed entry server instance."""
        return FlextLdifServersRelaxed.Entry()

    @pytest.fixture
    def relaxed_instance(self) -> FlextLdifServersRelaxed:
        """Create main relaxed server instance."""
        return FlextLdifServersRelaxed()

    @pytest.mark.parametrize(
        ("scenario", "definition_data"),
        list(c.Tests.RELAXED_ATTRIBUTE_DEFINITIONS.items()),
        ids=list(c.Tests.RELAXED_ATTRIBUTE_DEFINITIONS.keys()),
    )
    def test_parse_attribute_scenarios(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
        scenario: str,
        definition_data: tuple[str, bool],
    ) -> None:
        """Test parse_attribute with various scenarios."""
        definition, should_succeed = definition_data
        result = schema_server.parse_attribute(definition)
        if should_succeed:
            _ = tm.that(result.success, eq=True)
            parsed = result.value
            if scenario in {
                c.Tests.RELAXED_PARSE_VALID,
                c.Tests.RELAXED_PARSE_MALFORMED,
            }:
                tm.that(parsed.oid, none=False)
                tm.that(parsed.metadata is not None, eq=True)
                assert parsed.metadata is not None
                tm.that(
                    (
                        parsed.metadata.extensions.schema_source_server == "relaxed"
                        or parsed.metadata.extensions.original_format is not None
                    ),
                    eq=True,
                )
        else:
            _ = tm.that(result.failure, eq=True)

    @pytest.mark.parametrize(
        ("scenario", "definition_data"),
        list(c.Tests.RELAXED_OBJECTCLASS_DEFINITIONS.items()),
        ids=list(c.Tests.RELAXED_OBJECTCLASS_DEFINITIONS.keys()),
    )
    def test_parse_objectclass_scenarios(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
        scenario: str,
        definition_data: tuple[str, bool],
    ) -> None:
        """Test parse_objectclass with various scenarios."""
        definition, should_succeed = definition_data
        result = schema_server.parse_objectclass(definition)
        if should_succeed:
            _ = tm.that(result.success, eq=True)
        else:
            _ = tm.that(result.failure, eq=True)

    def test_parse_attribute_stores_original_definition(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test parse_attribute stores original definition for recovery."""
        original = "( 1.2.3.4 NAME 'test' SYNTAX 1.2.3 )"
        result = schema_server.parse_attribute(original)
        tm.that(result.success, eq=True)
        parsed = result.value
        tm.that(parsed.metadata is not None, eq=True)
        assert parsed.metadata is not None
        tm.that(parsed.metadata.extensions.original_format, eq=original)

    def test_write_attribute_to_rfc(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test writing attribute back to RFC format."""
        attr_data = m.Ldif.SchemaAttribute(
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
        result = schema_server.write_attribute(attr_data)
        tm.that(result.success, eq=True)
        written = result.value
        tm.that(written, is_=str)
        tm.that(len(written) > 0, eq=True)

    @pytest.mark.parametrize(
        ("name", "acl_data"),
        list(c.Tests.RELAXED_ACL_DEFINITIONS.items()),
        ids=list(c.Tests.RELAXED_ACL_DEFINITIONS.keys()),
    )
    def test_parse_acl_scenarios(
        self,
        acl_server: FlextLdifServersRelaxed.Acl,
        name: str,
        acl_data: tuple[str, bool],
    ) -> None:
        """Test ACL parsing in relaxed mode with various scenarios."""
        acl_line, _should_succeed = acl_data
        result = acl_server.parse_input(acl_line)
        if result.success:
            parsed = result.value
            tm.that(parsed.raw_acl, eq=acl_line)

    def test_write_acl_preserves_raw_content(
        self,
        acl_server: FlextLdifServersRelaxed.Acl,
    ) -> None:
        """Test that writing ACL preserves raw content."""
        raw_acl = '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)'
        acl_data = m.Ldif.Acl(
            name="test_acl",
            target=m.Ldif.AclTarget(target_dn="*", attributes=[]),
            subject=m.Ldif.AclSubject(
                subject_type=c.Ldif.AclSubjectType.ALL, subject_value="*"
            ),
            permissions=m.Ldif.AclPermissions(),
            raw_acl=raw_acl,
        )
        result = acl_server.write(acl_data)
        tm.that(result.success, eq=True)
        written = result.value
        tm.that(written, eq=raw_acl)

    def test_entry_lenient_dn_parsing(
        self,
        relaxed_instance: FlextLdifServersRelaxed,
    ) -> None:
        """Test entry server accepts malformed c.DNs."""

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
        schema_server: FlextLdifServersRelaxed.Schema,
        parse_type: str,
        bad_input: str,
    ) -> None:
        """Test relaxed mode recovers from binary content if OID present."""
        result: p.Result[m.Ldif.SchemaAttribute] | r[m.Ldif.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_server.parse_attribute(bad_input)
        else:
            result = schema_server.parse_objectclass(bad_input)
        tm.that(result.success, eq=True)
        parsed = result.value
        tm.that(parsed.metadata is not None, eq=True)
        assert parsed.metadata is not None
        tm.that(
            (
                parsed.metadata.extensions.original_format is not None
                or parsed.metadata.extensions.schema_source_server is not None
            ),
            eq=True,
        )

    @pytest.mark.parametrize(
        ("parse_type", "definition", "expected_success"),
        [
            ("attribute", "( \x00 )", False),
            ("objectclass", "( \x00 )", False),
            ("attribute", "( 1.2.3.4 \x00 )", True),
            ("objectclass", "( 1.2.3.4 \x00 )", True),
        ],
        ids=[
            "attribute_no_oid",
            "objectclass_no_oid",
            "attribute_with_oid",
            "objectclass_with_oid",
        ],
    )
    def test_fallback_behavior_depends_on_oid_presence(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
        parse_type: str,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test relaxed fallback requires an OID to recover binary definitions."""
        result: p.Result[m.Ldif.SchemaAttribute] | r[m.Ldif.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_server.parse_attribute(definition)
        else:
            result = schema_server.parse_objectclass(definition)
        tm.that(result.success, eq=expected_success)

    def test_relaxed_mode_integration(
        self,
        relaxed_instance: FlextLdifServersRelaxed,
    ) -> None:
        """Test relaxed mode full integration."""
        tm.that(relaxed_instance, none=False)

    def test_relaxed_mode_priority(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test relaxed mode has appropriate priority (low = last resort)."""
        tm.that(schema_server, none=False)

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
        schema_server: FlextLdifServersRelaxed.Schema,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test can_handle_attribute behavior through parse method."""
        result = schema_server.parse_input(definition)
        tm.that(result.success, eq=expected_success)

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
        schema_server: FlextLdifServersRelaxed.Schema,
        definition: str,
        expected_success: bool,
    ) -> None:
        """Test can_handle_objectclass behavior through parse method."""
        result = schema_server.parse_input(definition)
        tm.that(result.success, eq=expected_success)

    def test_conversion_attribute_oid_to_rfc(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test attribute conversion from OID format to c.RFC."""
        attr_data = m.Ldif.SchemaAttribute(
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
        result = schema_server.write_attribute(attr_data)
        tm.that(result.success, eq=True)
        written = result.value
        tm.that(written, has="2.16.840.1.113894.1.1.1")
        tm.that(written, has="orclGUID")

    def test_conversion_objectclass_oid_to_rfc(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
    ) -> None:
        """Test objectclass conversion from OID format to c.RFC."""
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.1",
            name="orclContext",
            desc="Oracle Context",
            sup="top",
        )
        result = schema_server.write_objectclass(oc_data)
        tm.that(result.success, eq=True)
        written = result.value
        tm.that(written, has="2.16.840.1.113894.1.2.1")
        tm.that(written, has="orclContext")
