"""Test suite for SchemaTransformer utility class.

Tests for the new SchemaTransformer class that handles generic schema
transformations used across OID, OUD, OpenLDAP, and other servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestSchemaTransformerNormalizeAttributeName:
    """Test normalize_attribute_name transformation."""

    def test_normalize_removes_binary_suffix(self) -> None:
        """Test that ;binary suffix is removed from attribute names."""
        result = FlextLdifUtilities.Schema.normalize_name(
            "userCertificate;binary",
            suffixes_to_remove=[";binary"],
        )
        assert result == "userCertificate"

    def test_normalize_replaces_underscores(self) -> None:
        """Test that underscores are replaced with hyphens."""
        result = FlextLdifUtilities.Schema.normalize_name(
            "oracle_oid_attribute",
            char_replacements={"_": "-"},
        )
        assert result == "oracle-oid-attribute"

    def test_normalize_removes_binary_and_underscores(self) -> None:
        """Test that both ;binary and underscores are normalized."""
        result = FlextLdifUtilities.Schema.normalize_name(
            "oracle_certificate;binary",
            suffixes_to_remove=[";binary"],
            char_replacements={"_": "-"},
        )
        assert result == "oracle-certificate"

    def test_normalize_rfc_compliant_name_unchanged(self) -> None:
        """Test that RFC-compliant names are unchanged."""
        result = FlextLdifUtilities.Schema.normalize_name("cn")
        assert result == "cn"

    def test_normalize_handles_empty_string(self) -> None:
        """Test that empty string is handled gracefully."""
        result = FlextLdifUtilities.Schema.normalize_name("")
        assert not result

    def test_normalize_handles_none(self) -> None:
        """Test that None is handled gracefully."""
        result = FlextLdifUtilities.Schema.normalize_name(None)
        assert result is None


class TestSchemaTransformerNormalizeMatchingRule:
    """Test normalize_matching_rule transformation."""

    def test_fix_substr_rule_in_equality_field(self) -> None:
        """Test that SUBSTR rules incorrectly in EQUALITY are fixed."""
        equality, substr = FlextLdifUtilities.Schema.normalize_matching_rules(
            "caseIgnoreSubstringsMatch",
            None,
            substr_rules_in_equality={"caseIgnoreSubstringsMatch": "caseIgnoreMatch"},
        )
        assert equality == "caseIgnoreMatch"
        assert substr == "caseIgnoreSubstringsMatch"

    def test_fix_substr_rule_capital_s(self) -> None:
        """Test that caseIgnoreSubStringsMatch (capital S) is handled."""
        equality, substr = FlextLdifUtilities.Schema.normalize_matching_rules(
            "caseIgnoreSubStringsMatch",
            None,
            normalized_substr_values={
                "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
            },
            substr_rules_in_equality={"caseIgnoreSubStringsMatch": "caseIgnoreMatch"},
        )
        assert equality == "caseIgnoreMatch"
        assert substr == "caseIgnoreSubstringsMatch"

    def test_apply_matching_rule_replacements(self) -> None:
        """Test that server-specific matching rule replacements are applied."""
        replacements = {
            "accessDirectiveMatch": "caseIgnoreMatch",
        }
        equality, substr = FlextLdifUtilities.Schema.normalize_matching_rules(
            "accessDirectiveMatch",
            None,
            replacements=replacements,
        )
        assert equality == "caseIgnoreMatch"
        assert substr is None

    def test_rfc_compliant_rule_unchanged(self) -> None:
        """Test that RFC-compliant rules are unchanged."""
        equality, substr = FlextLdifUtilities.Schema.normalize_matching_rules(
            "caseIgnoreMatch",
            None,
        )
        assert equality == "caseIgnoreMatch"
        assert substr is None

    def test_preserve_existing_substr(self) -> None:
        """Test that existing SUBSTR rules are preserved."""
        equality, substr = FlextLdifUtilities.Schema.normalize_matching_rules(
            "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch",
        )
        assert equality == "caseIgnoreMatch"
        assert substr == "caseIgnoreSubstringsMatch"


class TestSchemaTransformerNormalizeSyntaxOid:
    """Test normalize_syntax_oid transformation."""

    def test_remove_quotes_from_syntax(self) -> None:
        """Test that quotes are removed from syntax OIDs."""
        result = FlextLdifUtilities.Schema.normalize_syntax_oid(
            "'1.3.6.1.4.1.1466.115.121.1.15'",
        )
        assert result == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_apply_syntax_replacements(self) -> None:
        """Test that server-specific syntax replacements are applied."""
        replacements = {"1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"}
        result = FlextLdifUtilities.Schema.normalize_syntax_oid(
            "1.3.6.1.4.1.1466.115.121.1.1",
            replacements=replacements,
        )
        assert result == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_rfc_compliant_syntax_unchanged(self) -> None:
        """Test that RFC-compliant syntax OIDs are unchanged."""
        result = FlextLdifUtilities.Schema.normalize_syntax_oid(
            "1.3.6.1.4.1.1466.115.121.1.15",
        )
        assert result == "1.3.6.1.4.1.1466.115.121.1.15"


class TestSchemaTransformerApplyAttributeTransformations:
    """Test apply_attribute_transformations pipeline."""

    def test_apply_all_transformations(self) -> None:
        """Test applying all three transformations to an attribute."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn;binary",
            equality="caseIgnoreSubstringsMatch",
            syntax="'1.3.6.1.4.1.1466.115.121.1.1'",
        )

        field_transforms = {
            "name": lambda n: FlextLdifUtilities.Schema.normalize_name(
                str(n) if n else n,
                suffixes_to_remove=[";binary"],
                char_replacements={"_": "-"},
            ),
            "equality": lambda eq: FlextLdifUtilities.Schema.normalize_matching_rules(
                str(eq) if eq else None,
                None,  # substr is None initially
                substr_rules_in_equality={
                    "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                },
            )[0],
            "substr": lambda sub: FlextLdifUtilities.Schema.normalize_matching_rules(
                attr.equality,
                str(sub) if sub else None,
                substr_rules_in_equality={
                    "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                },
            )[1],
            "syntax": lambda syn: FlextLdifUtilities.Schema.normalize_syntax_oid(
                str(syn) if syn else None,
                replacements={
                    "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",
                },
            ),
        }
        result = FlextLdifUtilities.Schema.apply_transformations(
            attr,
            field_transforms=field_transforms,
        )

        assert result.is_success
        transformed = result.unwrap()
        assert transformed.name == "cn"
        assert transformed.equality == "caseIgnoreMatch"
        assert transformed.substr == "caseIgnoreSubstringsMatch"
        assert transformed.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_partial_transformations(self) -> None:
        """Test applying only some transformations."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn;binary",
            equality="caseIgnoreMatch",
        )

        field_transforms = {
            "name": lambda n: FlextLdifUtilities.Schema.normalize_name(
                str(n) if n else n,
                suffixes_to_remove=[";binary"],
                char_replacements={"_": "-"},
            ),
        }
        result = FlextLdifUtilities.Schema.apply_transformations(
            attr,
            field_transforms=field_transforms,
        )

        assert result.is_success
        transformed = result.unwrap()
        assert transformed.name == "cn"
        assert transformed.equality == "caseIgnoreMatch"


class TestSchemaTransformerApplyObjectClassTransformations:
    """Test apply_objectclass_transformations pipeline."""

    def test_apply_objectclass_transformations(self) -> None:
        """Test transforming an objectClass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.0",
            name="top",
        )

        result = FlextLdifUtilities.Schema.apply_transformations(
            oc,
            field_transforms=None,
        )

        assert result.is_success
        transformed = result.unwrap()
        assert transformed.name == "top"
        assert transformed.oid == "2.5.6.0"
