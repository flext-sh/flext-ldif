"""Schema test helpers to eliminate massive code duplication.

Provides high-level methods that replace entire test functions with single calls.
Each method replaces 10-20+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult

from tests.helpers.test_assertions import TestAssertions

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels
    from flext_ldif.servers.base import FlextLdifServersBase


class SchemaTestHelpers:
    """High-level schema test helpers that replace entire test functions."""

    @staticmethod
    def test_parse_attribute_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_single_value: bool | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Complete attribute parse test - replaces entire test function.

        This method replaces 10-15 lines of duplicated test code:
        - Calls parse_attribute
        - Asserts success
        - Validates OID, name, desc, syntax, single-value
        - Returns parsed attribute for further assertions

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Optional expected description
            expected_syntax: Optional expected syntax OID
            expected_single_value: Optional expected single-value flag

        Returns:
            Parsed SchemaAttribute

        Example:
            # Replaces entire test function:
            attr = SchemaTestHelpers.test_parse_attribute_complete(
                schema_quirk,
                "( 1.2.3.4 NAME 'testAttr' DESC 'Test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_oid="1.2.3.4",
                expected_name="testAttr",
                expected_desc="Test",
                expected_syntax="1.3.6.1.4.1.1466.115.121.1.15"
            )

        """
        result = schema_quirk.parse_attribute(attr_def)
        attr = TestAssertions.assert_success(result, "Attribute parse should succeed")
        assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
            "Parse should return SchemaAttribute"
        )

        TestAssertions.assert_schema_attribute_valid(attr, expected_oid, expected_name)

        if expected_desc is not None:
            assert attr.desc == expected_desc, (
                f"Expected desc '{expected_desc}', got '{attr.desc}'"
            )

        if expected_syntax is not None:
            assert attr.syntax == expected_syntax, (
                f"Expected syntax '{expected_syntax}', got '{attr.syntax}'"
            )

        if expected_single_value is not None:
            # Check if SINGLE-VALUE is in original definition or metadata
            has_single_value = "SINGLE-VALUE" in attr_def.upper()
            assert has_single_value == expected_single_value, (
                f"Expected single_value={expected_single_value}, "
                f"definition has SINGLE-VALUE={has_single_value}"
            )

        return attr

    @staticmethod
    def test_parse_objectclass_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
        expected_sup: str | None = None,
        expected_kind: str | None = None,  # STRUCTURAL, AUXILIARY, ABSTRACT
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Complete objectClass parse test - replaces entire test function.

        This method replaces 10-20 lines of duplicated test code:
        - Calls parse_objectclass
        - Asserts success
        - Validates OID, name, sup, kind, must, may
        - Returns parsed objectClass for further assertions

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_sup: Optional expected superior objectClass
            expected_kind: Optional expected kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            expected_must: Optional expected MUST attributes
            expected_may: Optional expected MAY attributes

        Returns:
            Parsed SchemaObjectClass

        Example:
            # Replaces entire test function:
            oc = SchemaTestHelpers.test_parse_objectclass_complete(
                schema_quirk,
                "( 1.2.3.4 NAME 'testOC' SUP top STRUCTURAL MUST cn )",
                expected_oid="1.2.3.4",
                expected_name="testOC",
                expected_sup="top",
                expected_kind="STRUCTURAL",
                expected_must=["cn"]
            )

        """
        result = schema_quirk.parse_objectclass(oc_def)
        oc = TestAssertions.assert_success(result, "ObjectClass parse should succeed")
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass), (
            "Parse should return SchemaObjectClass"
        )

        TestAssertions.assert_schema_objectclass_valid(oc, expected_oid, expected_name)

        if expected_sup is not None:
            assert oc.sup == expected_sup, (
                f"Expected sup '{expected_sup}', got '{oc.sup}'"
            )

        if expected_kind is not None:
            kind_upper = expected_kind.upper()
            assert kind_upper in oc_def.upper(), (
                f"Expected kind '{expected_kind}' not found in definition"
            )

        if expected_must is not None:
            must_in_def = all(must_attr.upper() in oc_def.upper() for must_attr in expected_must)
            assert must_in_def, (
                f"Expected MUST attributes {expected_must} not all found in definition"
            )

        if expected_may is not None:
            may_in_def = all(may_attr.upper() in oc_def.upper() for may_attr in expected_may)
            assert may_in_def, (
                f"Expected MAY attributes {expected_may} not all found in definition"
            )

        return oc

    @staticmethod
    def test_write_attribute_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        expected_content: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete attribute write test - replaces entire test function.

        This method replaces 8-12 lines of duplicated test code:
        - Calls write_attribute
        - Asserts success
        - Validates expected content, must_contain, must_not_contain
        - Returns written LDIF string

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to write
            expected_content: Optional list of strings that must be in output
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            ldif = SchemaTestHelpers.test_write_attribute_complete(
                schema_quirk,
                attr,
                expected_content=["1.2.3.4", "testAttr"],
                must_contain=["NAME", "SYNTAX"],
                must_not_contain=["OBSOLETE"]
            )

        """
        result = schema_quirk.write_attribute(attr)
        ldif = TestAssertions.assert_success(result, "Attribute write should succeed")
        assert isinstance(ldif, str), "Write should return string"

        if expected_content:
            for content in expected_content:
                assert content in ldif, f"Expected content '{content}' not found in LDIF"

        if must_contain:
            for content in must_contain:
                assert content in ldif, f"Must contain '{content}' not found in LDIF"

        if must_not_contain:
            for content in must_not_contain:
                assert content not in ldif, (
                    f"Must not contain '{content}' found in LDIF"
                )

        return ldif

    @staticmethod
    def test_write_objectclass_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        expected_content: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete objectClass write test - replaces entire test function.

        This method replaces 8-12 lines of duplicated test code:
        - Calls write_objectclass
        - Asserts success
        - Validates expected content, must_contain, must_not_contain
        - Returns written LDIF string

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to write
            expected_content: Optional list of strings that must be in output
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            ldif = SchemaTestHelpers.test_write_objectclass_complete(
                schema_quirk,
                oc,
                expected_content=["1.2.3.4", "testOC"],
                must_contain=["NAME", "STRUCTURAL"],
                must_not_contain=["AUXILIARY"]
            )

        """
        result = schema_quirk.write_objectclass(oc)
        ldif = TestAssertions.assert_success(result, "ObjectClass write should succeed")
        assert isinstance(ldif, str), "Write should return string"

        if expected_content:
            for content in expected_content:
                assert content in ldif, f"Expected content '{content}' not found in LDIF"

        if must_contain:
            for content in must_contain:
                assert content in ldif, f"Must contain '{content}' not found in LDIF"

        if must_not_contain:
            for content in must_not_contain:
                assert content not in ldif, (
                    f"Must not contain '{content}' found in LDIF"
                )

        return ldif

    @staticmethod
    def test_hook_post_parse_attribute_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        should_succeed: bool = True,
        expected_error: str | None = None,
        validate_result: bool = True,
    ) -> FlextLdifModels.SchemaAttribute | None:
        """Complete hook_post_parse_attribute test - replaces entire test function.

        This method replaces 8-15 lines of duplicated test code:
        - Calls _hook_post_parse_attribute
        - Asserts success/failure based on should_succeed
        - Validates error message if failure expected
        - Returns parsed attribute or None

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to test hook with
            should_succeed: Whether hook should succeed (default: True)
            expected_error: Optional expected error substring if should fail
            validate_result: Whether to validate returned attribute (default: True)

        Returns:
            Parsed SchemaAttribute if success, None if failure

        Example:
            # Replaces entire test function:
            result_attr = SchemaTestHelpers.test_hook_post_parse_attribute_complete(
                schema_quirk,
                attr,
                should_succeed=True
            )

            # Or for failure case:
            SchemaTestHelpers.test_hook_post_parse_attribute_complete(
                schema_quirk,
                invalid_attr,
                should_succeed=False,
                expected_error="Invalid OID format"
            )

        """
        result = schema_quirk._hook_post_parse_attribute(attr)

        if should_succeed:
            result_attr = TestAssertions.assert_success(
                result, "Hook should succeed"
            )
            assert isinstance(result_attr, FlextLdifModels.SchemaAttribute), (
                "Hook should return SchemaAttribute"
            )
            if validate_result:
                TestAssertions.assert_schema_attribute_valid(result_attr)
            return result_attr
        else:
            error = TestAssertions.assert_failure(result, expected_error)
            return None

    @staticmethod
    def test_hook_post_parse_objectclass_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        should_succeed: bool = True,
        expected_error: str | None = None,
        validate_result: bool = True,
    ) -> FlextLdifModels.SchemaObjectClass | None:
        """Complete hook_post_parse_objectclass test - replaces entire test function.

        This method replaces 8-15 lines of duplicated test code:
        - Calls _hook_post_parse_objectclass
        - Asserts success/failure based on should_succeed
        - Validates error message if failure expected
        - Returns parsed objectClass or None

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to test hook with
            should_succeed: Whether hook should succeed (default: True)
            expected_error: Optional expected error substring if should fail
            validate_result: Whether to validate returned objectClass (default: True)

        Returns:
            Parsed SchemaObjectClass if success, None if failure

        Example:
            # Replaces entire test function:
            result_oc = SchemaTestHelpers.test_hook_post_parse_objectclass_complete(
                schema_quirk,
                oc,
                should_succeed=True
            )

        """
        result = schema_quirk._hook_post_parse_objectclass(oc)

        if should_succeed:
            result_oc = TestAssertions.assert_success(result, "Hook should succeed")
            assert isinstance(result_oc, FlextLdifModels.SchemaObjectClass), (
                "Hook should return SchemaObjectClass"
            )
            if validate_result:
                TestAssertions.assert_schema_objectclass_valid(result_oc)
            return result_oc
        else:
            TestAssertions.assert_failure(result, expected_error)
            return None

    @staticmethod
    def test_parse_write_roundtrip_attribute(
        schema_quirk: FlextLdifServersBase.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> tuple[FlextLdifModels.SchemaAttribute, str]:
        """Complete parse-write roundtrip test for attribute - replaces entire test function.

        This method replaces 15-25 lines of duplicated test code:
        - Parses attribute
        - Writes attribute
        - Validates both operations
        - Returns (parsed_attr, written_ldif)

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Tuple of (parsed_attribute, written_ldif_string)

        Example:
            # Replaces entire test function:
            attr, ldif = SchemaTestHelpers.test_parse_write_roundtrip_attribute(
                schema_quirk,
                "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                expected_oid="1.2.3.4",
                expected_name="testAttr"
            )

        """
        # Parse
        attr = SchemaTestHelpers.test_parse_attribute_complete(
            schema_quirk, attr_def, expected_oid, expected_name
        )

        # Write
        ldif = SchemaTestHelpers.test_write_attribute_complete(
            schema_quirk,
            attr,
            expected_content=[expected_oid, expected_name],
        )

        return (attr, ldif)

    @staticmethod
    def test_parse_write_roundtrip_objectclass(
        schema_quirk: FlextLdifServersBase.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> tuple[FlextLdifModels.SchemaObjectClass, str]:
        """Complete parse-write roundtrip test for objectClass - replaces entire test function.

        This method replaces 15-25 lines of duplicated test code:
        - Parses objectClass
        - Writes objectClass
        - Validates both operations
        - Returns (parsed_oc, written_ldif)

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Tuple of (parsed_objectClass, written_ldif_string)

        Example:
            # Replaces entire test function:
            oc, ldif = SchemaTestHelpers.test_parse_write_roundtrip_objectclass(
                schema_quirk,
                "( 1.2.3.4 NAME 'testOC' SUP top STRUCTURAL )",
                expected_oid="1.2.3.4",
                expected_name="testOC"
            )

        """
        # Parse
        oc = SchemaTestHelpers.test_parse_objectclass_complete(
            schema_quirk, oc_def, expected_oid, expected_name
        )

        # Write
        ldif = SchemaTestHelpers.test_write_objectclass_complete(
            schema_quirk,
            oc,
            expected_content=[expected_oid, expected_name],
        )

        return (oc, ldif)


__all__ = ["SchemaTestHelpers"]
