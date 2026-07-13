"""Tests for Relaxed server LDIF servers handling.

This module tests the Relaxed implementation for lenient parsing of malformed LDIF,
accepting entries that don't conform strictly to RFC standards while preserving content.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from tests.constants import c
from tests.models import m
from tests.typings import t

if TYPE_CHECKING:
    from tests.protocols import p


@pytest.mark.unit
class TestsFlextLdifRelaxed:
    """Behavioral test suite for the Relaxed server public contract.

    Covers observable behavior only:
    - Schema servers (attribute/objectclass parse/write results as ``r[T]``)
    - ACL servers (parse/write raw-content preservation)
    - Entry servers (lenient DN normalization contract)
    - Error recovery and edge cases via public model state
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
                        parsed.metadata.extensions.get("schema_source_server")
                        == "relaxed"
                        or parsed.metadata.extensions.get("original_format")
                        is not None
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
        parsed = tm.ok(schema_server.parse_attribute(original))
        assert parsed.metadata is not None
        tm.that(parsed.metadata.extensions.get("original_format"), eq=original)

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
        written = tm.ok(schema_server.write_attribute(attr_data))
        tm.that(written, is_=str)
        tm.that(len(written), gt=0)

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
                subject_type=c.Ldif.AclSubjectType.ALL,
                subject_value="*",
            ),
            permissions=m.Ldif.AclPermissions(),
            raw_acl=raw_acl,
        )
        tm.that(tm.ok(acl_server.write(acl_data)), eq=raw_acl)

    @pytest.mark.parametrize(
        ("raw_dn", "normalized"),
        [
            ("cn=Test, dc=Example", "cn=Test,dc=Example"),
            ("cn=Test,dc=Example", "cn=Test,dc=Example"),
            ("  cn=x , dc=y  ", "cn=x,dc=y"),
        ],
        ids=["spaces_after_comma", "already_tight", "leading_trailing_space"],
    )
    def test_entry_normalize_dn_strips_incidental_whitespace(
        self,
        entry_server: FlextLdifServersRelaxed.Entry,
        raw_dn: str,
        normalized: str,
    ) -> None:
        """normalize_dn returns the whitespace-normalized DN on success."""
        result = entry_server.normalize_dn(raw_dn)
        tm.that(result.success, eq=True)
        tm.that(tm.ok(result), eq=normalized)

    @pytest.mark.parametrize(
        ("bad_dn", "error_fragment"),
        [
            ("", "empty"),
            ("not a dn at all", "missing '=' separator"),
        ],
        ids=["empty_dn", "no_separator"],
    )
    def test_entry_normalize_dn_fails_on_unrecoverable_input(
        self,
        entry_server: FlextLdifServersRelaxed.Entry,
        bad_dn: str,
        error_fragment: str,
    ) -> None:
        """normalize_dn surfaces a failure r[T] for unrecoverable DNs."""
        result = entry_server.normalize_dn(bad_dn)
        tm.that(result.failure, eq=True)
        tm.that(result.error, has=[error_fragment])

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
        result: p.Result[m.Ldif.SchemaAttribute] | p.Result[m.Ldif.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_server.parse_attribute(bad_input)
        else:
            result = schema_server.parse_objectclass(bad_input)
        parsed = tm.ok(result)
        assert parsed.metadata is not None
        ext = parsed.metadata.extensions
        tm.that(
            ext.get("original_format") is not None
            or ext.get("schema_source_server") is not None,
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
        result: p.Result[m.Ldif.SchemaAttribute] | p.Result[m.Ldif.SchemaObjectClass]
        if parse_type == "attribute":
            result = schema_server.parse_attribute(definition)
        else:
            result = schema_server.parse_objectclass(definition)
        tm.that(result.success, eq=expected_success)

    @pytest.mark.parametrize(
        "definition",
        [
            "( 1.2.3 NAME 'valid' )",
            "MALFORMED",
            "( 1.2.3 \x00 garbage )",
        ],
        ids=["valid", "malformed", "binary_noise"],
    )
    def test_schema_can_handle_attribute_accepts_anything(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
        definition: str,
    ) -> None:
        """Relaxed is the last-resort handler: can_handle_attribute is always True."""
        tm.that(schema_server.can_handle_attribute(definition), eq=True)

    @pytest.mark.parametrize(
        "definition",
        [
            "( 1.2.3 NAME 'valid' STRUCTURAL )",
            "BROKEN CLASS",
            "( 1.2.3 \x00 garbage )",
        ],
        ids=["valid", "malformed", "binary_noise"],
    )
    def test_schema_can_handle_objectclass_accepts_anything(
        self,
        schema_server: FlextLdifServersRelaxed.Schema,
        definition: str,
    ) -> None:
        """Relaxed is the last-resort handler: can_handle_objectclass is always True."""
        tm.that(schema_server.can_handle_objectclass(definition), eq=True)

    @pytest.mark.parametrize(
        ("entry_dn", "attributes"),
        [
            ("cn=x,dc=y", {"cn": ["x"]}),
            ("", {}),
            ("garbled dn", {"weird": ["v"]}),
        ],
        ids=["well_formed", "empty", "malformed"],
    )
    def test_entry_can_handle_accepts_any_entry(
        self,
        entry_server: FlextLdifServersRelaxed.Entry,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> None:
        """Relaxed entry server claims every entry, well-formed or not."""
        tm.that(entry_server.can_handle(entry_dn, attributes), eq=True)

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
        written = tm.ok(schema_server.write_attribute(attr_data))
        tm.that(written, has=["2.16.840.1.113894.1.1.1", "orclGUID"])

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
        written = tm.ok(schema_server.write_objectclass(oc_data))
        tm.that(written, has=["2.16.840.1.113894.1.2.1", "orclContext"])
