"""Tests for OID (Oracle Internet Directory) servers."""

from __future__ import annotations

import pytest

from flext_ldif.services.server import FlextLdifServer


class TestsTestFlextLdifOidServers:
    """Test OID-specific servers and behavior."""

    @pytest.fixture
    def server_registry(self) -> FlextLdifServer:
        """Create server registry."""
        return FlextLdifServer()

    def test_parse_attribute_syntax_oid_normalization(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID Boolean syntax should normalize to RFC DirectoryString."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclIsEnabled' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        attr = result.value
        assert str(attr.syntax) == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_parse_attribute_matching_rule_normalization(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID equality substrings rule should normalize to RFC fields."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "DESC 'UI type via DAS' EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE "
            "USAGE userApplications )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        attr = result.value
        assert attr.equality == "caseIgnoreMatch"
        assert attr.substr == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_access_directive_match(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID-specific accessDirectiveMatch should normalize to caseIgnoreMatch."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.500 NAME 'orclAccessDir' "
            "EQUALITY accessDirectiveMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.value.equality == "caseIgnoreMatch"

    def test_parse_attribute_distinguished_name_case_variant(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID DN case variants should normalize to distinguishedNameMatch."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.600 NAME 'orclMemberRef' "
            "EQUALITY distinguishedNAMEMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.value.equality == "distinguishedNameMatch"

    def test_parse_objectclass_quoted_sup(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """Quoted SUP 'top' should parse as bare top."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        oc_def = (
            "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
            "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )"
        )
        result = schema.parse_objectclass(oc_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.value.sup == "top"

    def test_parse_objectclass_auxiliary_typo(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID AUXILLARY typo should normalize to AUXILIARY."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        oc_def = (
            "( 2.16.840.1.113894.1.2.99 NAME 'orclTestAux' "
            "SUP top AUXILLARY MAY ( cn ) )"
        )
        result = schema.parse_objectclass(oc_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.value.kind == "AUXILIARY"

    def test_parse_objectclass_parenthesized_sup(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """Parenthesized SUP should parse as a single superior class."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        oc_def = (
            "( 2.16.840.1.113894.1.2.50 NAME 'orclParenSup' "
            "SUP ( top ) STRUCTURAL MAY ( cn ) )"
        )
        result = schema.parse_objectclass(oc_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.value.sup == "top"

    def test_write_attribute_preserves_matching_rules(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """OID same-server round-trip should preserve original matching-rule text."""
        schema = server_registry.resolve_schema_server("oid")
        assert schema is not None
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        parse_result = schema.parse_attribute(attr_def)
        assert parse_result.success, f"Parse failed: {parse_result.error}"
        write_result = schema.write_attribute(parse_result.value)
        assert write_result.success, f"Write failed: {write_result.error}"
        written = write_result.value
        assert "EQUALITY caseIgnoreSubstringsMatch" in written


__all__: list[str] = ["TestsTestFlextLdifOidServers"]
