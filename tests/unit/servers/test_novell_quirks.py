"""Tests for Novell eDirectory (NDS) server-specific LDIF quirks handling.

This module tests the FlextLdifServersNovell implementation for handling Novell
eDirectory-specific attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifServersNovell
from tests import c, m, u


@pytest.fixture
def novell_server() -> FlextLdifServersNovell:
    """Create Novell server instance."""
    return FlextLdifServersNovell()


@pytest.fixture
def schema_quirk(
    novell_server: FlextLdifServersNovell,
) -> FlextLdifServersNovell.Schema:
    """Get schema quirk from Novell server."""
    quirk = novell_server.schema_quirk
    assert isinstance(quirk, FlextLdifServersNovell.Schema)
    return quirk


@pytest.fixture
def entry_quirk(novell_server: FlextLdifServersNovell) -> FlextLdifServersNovell.Entry:
    """Get entry quirk from Novell server."""
    quirk = novell_server.entry_quirk
    assert isinstance(quirk, FlextLdifServersNovell.Entry)
    return quirk


class TestsFlextLdifNovellQuirks:
    """Test initialization of Novell quirks."""

    """Test schema attribute detection."""

    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute(
        self,
        test_case: m.Tests.AttributeTestCase,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test attribute detection for various scenarios."""
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    """Test schema attribute parsing."""

    def test_parse_attribute_success(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing Novell eDirectory attribute definition."""
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' DESC 'Password Policy DN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        u.Tests.assert_quirk_schema_parse_and_properties(
            schema_quirk,
            attr_def,
            expected_oid="2.16.840.1.113719.1.1.4.1.501",
            expected_name="nspmPasswordPolicyDN",
            expected_desc="Password Policy DN",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_with_syntax_length(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing attribute with syntax length specification."""
        attr_def = "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        u.Tests.assert_quirk_schema_parse_and_properties(
            schema_quirk,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing attribute without OID fails."""
        attr_def = "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = schema_quirk.parse_attribute(attr_def)
        tm.that(result.failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error, has="missing an OID")

    """Test schema objectClass detection."""

    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass(
        self,
        test_case: m.Tests.ObjectClassTestCase,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test objectClass detection for various scenarios."""
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    """Test schema objectClass parsing."""

    def test_parse_objectclass_structural(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        u.Tests.assert_quirk_schema_parse_and_properties(
            schema_quirk,
            oc_def,
            expected_oid="2.16.840.1.113719.2.2.6.1",
            expected_name="ndsPerson",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["loginDisabled"],
        )

    def test_parse_objectclass_auxiliary(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        u.Tests.assert_quirk_schema_parse_and_properties(
            schema_quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        u.Tests.assert_quirk_schema_parse_and_properties(
            schema_quirk,
            oc_def,
            expected_kind="ABSTRACT",
        )

    def test_parse_objectclass_missing_oid(
        self,
        schema_quirk: FlextLdifServersNovell.Schema,
    ) -> None:
        """Test parsing objectClass without OID fails."""
        oc_def = "NAME 'ndsPerson' SUP top STRUCTURAL"
        quirk_schema = schema_quirk
        result = quirk_schema.parse_objectclass(oc_def)
        tm.that(result.failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error, has="missing an OID")

    """Test entry detection."""

    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_ENTRY_TEST_CASES)
    def test_can_handle_entry(
        self,
        test_case: m.Tests.EntryTestCase,
        entry_quirk: FlextLdifServersNovell.Entry,
    ) -> None:
        """Test entry detection for various scenarios."""
        quirk_entry = entry_quirk
        result = quirk_entry.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)
