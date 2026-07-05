"""Behavioral tests for the OID (Oracle Internet Directory) schema server.

Asserts observable public contract only: values returned by
``resolve_schema_server`` and the ``r[T]`` outcomes of ``parse_attribute`` /
``parse_objectclass`` / ``write_attribute`` / ``write_objectclass``. No private
attribute access, no internal-collaborator spying, no patching of the unit
under test.
"""

from __future__ import annotations

import pytest

from flext_ldif import p
from flext_ldif.services.server import FlextLdifServer


class TestsFlextLdifOidServers:
    """Public-contract behavior of the OID schema server."""

    @pytest.fixture
    def schema(self) -> p.Ldif.SchemaServer:
        """Resolve the OID schema server through the public registry."""
        resolved = FlextLdifServer().resolve_schema_server("oid")
        assert resolved is not None, "OID schema server must be registered"
        return resolved

    def test_resolve_unknown_server_type_returns_none(self) -> None:
        """An unknown server type resolves to None, not a fabricated server."""
        assert FlextLdifServer().resolve_schema_server("does-not-exist") is None

    @pytest.mark.parametrize(
        ("attr_def", "expected_syntax"),
        [
            pytest.param(
                "( 2.16.840.1.113894.1.1.1 NAME 'orclIsEnabled' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 SINGLE-VALUE )",
                "1.3.6.1.4.1.1466.115.121.1.15",
                id="boolean-syntax-normalized-to-directorystring",
            ),
            pytest.param(
                "( 2.16.840.1.113894.1.1.2 NAME 'orclDirString' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                "1.3.6.1.4.1.1466.115.121.1.15",
                id="rfc-syntax-preserved",
            ),
        ],
    )
    def test_parse_attribute_normalizes_syntax_oid(
        self,
        schema: p.Ldif.SchemaServer,
        attr_def: str,
        expected_syntax: str,
    ) -> None:
        """OID-specific syntax OIDs normalize to their RFC equivalent."""
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        assert str(result.unwrap().syntax) == expected_syntax

    @pytest.mark.parametrize(
        ("equality_in", "expected_equality"),
        [
            pytest.param(
                "caseIgnoreSubstringsMatch",
                "caseIgnoreMatch",
                id="substrings-equality-normalized",
            ),
            pytest.param(
                "accessDirectiveMatch",
                "caseIgnoreMatch",
                id="oid-access-directive-normalized",
            ),
            pytest.param(
                "distinguishedNAMEMatch",
                "distinguishedNameMatch",
                id="dn-case-variant-normalized",
            ),
        ],
    )
    def test_parse_attribute_normalizes_equality_matching_rule(
        self,
        schema: p.Ldif.SchemaServer,
        equality_in: str,
        expected_equality: str,
    ) -> None:
        """OID equality matching-rule variants normalize to RFC rule names."""
        attr_def = (
            f"( 2.16.840.1.113894.1.1.327 NAME 'orclAttr' "
            f"EQUALITY {equality_in} "
            f"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.unwrap().equality == expected_equality

    def test_parse_attribute_derives_substr_from_substrings_rule(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """A substrings equality rule populates the public substr field."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "DESC 'UI type via DAS' EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE "
            "USAGE userApplications )"
        )
        result = schema.parse_attribute(attr_def)
        assert result.success, f"Parse failed: {result.error}"
        attr = result.unwrap()
        assert attr.equality == "caseIgnoreMatch"
        assert attr.substr == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_exposes_public_identity_fields(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """Parsed attribute exposes name, oid, and flags via the public model."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        attr = schema.parse_attribute(attr_def).unwrap()
        assert attr.name == "orclDASUIType"
        assert attr.oid == "2.16.840.1.113894.1.1.327"
        assert attr.single_value is True

    def test_parse_attribute_without_oid_fails_with_error_message(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """A definition lacking an OID yields a failed result, not a success."""
        result = schema.parse_attribute("garbage not valid")
        assert result.success is False
        assert result.error is not None
        assert "OID" in result.error

    @pytest.mark.parametrize(
        ("oc_def", "expected_sup"),
        [
            pytest.param(
                "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
                "SUP 'top' STRUCTURAL MAY ( orclOwnerGUID $ seeAlso ) )",
                "top",
                id="quoted-sup-top",
            ),
            pytest.param(
                "( 2.16.840.1.113894.1.2.50 NAME 'orclParenSup' "
                "SUP ( top ) STRUCTURAL MAY ( cn ) )",
                "top",
                id="parenthesized-sup",
            ),
        ],
    )
    def test_parse_objectclass_normalizes_superior(
        self,
        schema: p.Ldif.SchemaServer,
        oc_def: str,
        expected_sup: str,
    ) -> None:
        """Quoted and parenthesized SUP forms both resolve to a bare superior."""
        result = schema.parse_objectclass(oc_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.unwrap().sup == expected_sup

    def test_parse_objectclass_normalizes_auxiliary_typo(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """The OID 'AUXILLARY' typo normalizes to the RFC AUXILIARY kind."""
        oc_def = (
            "( 2.16.840.1.113894.1.2.99 NAME 'orclTestAux' "
            "SUP top AUXILLARY MAY ( cn ) )"
        )
        result = schema.parse_objectclass(oc_def)
        assert result.success, f"Parse failed: {result.error}"
        assert result.unwrap().kind == "AUXILIARY"

    def test_write_attribute_round_trip_preserves_matching_rule_text(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """Same-server round-trip preserves the original matching-rule text."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.327 NAME 'orclDASUIType' "
            "EQUALITY caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        parsed = schema.parse_attribute(attr_def)
        assert parsed.success, f"Parse failed: {parsed.error}"
        written = schema.write_attribute(parsed.unwrap())
        assert written.success, f"Write failed: {written.error}"
        assert "EQUALITY caseIgnoreSubstringsMatch" in written.unwrap()

    def test_write_objectclass_round_trip_preserves_identity(
        self,
        schema: p.Ldif.SchemaServer,
    ) -> None:
        """Objectclass round-trip preserves name and superior in the output."""
        oc_def = (
            "( 2.16.840.1.113894.1.2.64 NAME 'orclReferenceObject' "
            "SUP top STRUCTURAL MAY ( cn ) )"
        )
        parsed = schema.parse_objectclass(oc_def)
        assert parsed.success, f"Parse failed: {parsed.error}"
        written = schema.write_objectclass(parsed.unwrap())
        assert written.success, f"Write failed: {written.error}"
        rendered = written.unwrap()
        assert "NAME 'orclReferenceObject'" in rendered
        assert "SUP top" in rendered


__all__: list[str] = ["TestsFlextLdifOidServers"]
