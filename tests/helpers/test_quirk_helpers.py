"""Quirk test helpers to eliminate massive code duplication.

Provides high-level methods for testing server quirks (Schema, Entry, ACL).
Each method replaces 10-30+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase

from .test_schema_helpers import SchemaTestHelpers


class QuirkTestHelpers:
    """High-level quirk test helpers that replace entire test functions."""

    @staticmethod
    def test_schema_parse_and_validate_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Complete schema attribute parse and validate - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Optional expected description
            expected_syntax: Optional expected syntax OID

        Returns:
            Parsed SchemaAttribute

        """
        return SchemaTestHelpers.test_parse_attribute_complete(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
            expected_desc=expected_desc,
            expected_syntax=expected_syntax,
        )

    @staticmethod
    def test_schema_parse_objectclass_and_validate_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
        expected_sup: str | None = None,
        expected_kind: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Complete schema objectClass parse and validate - replaces entire test function.

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

        """
        return SchemaTestHelpers.test_parse_objectclass_complete(
            schema_quirk,
            oc_def,
            expected_oid,
            expected_name,
            expected_sup=expected_sup,
            expected_kind=expected_kind,
            expected_must=expected_must,
            expected_may=expected_may,
        )

    @staticmethod
    def test_schema_write_and_validate_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        expected_content: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete schema attribute write and validate - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to write
            expected_content: Optional list of strings that must be in output
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        """
        return SchemaTestHelpers.test_write_attribute_complete(
            schema_quirk,
            attr,
            expected_content=expected_content,
            must_contain=must_contain,
            must_not_contain=must_not_contain,
        )

    @staticmethod
    def test_schema_write_objectclass_and_validate_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        expected_content: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete schema objectClass write and validate - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to write
            expected_content: Optional list of strings that must be in output
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        """
        return SchemaTestHelpers.test_write_objectclass_complete(
            schema_quirk,
            oc,
            expected_content=expected_content,
            must_contain=must_contain,
            must_not_contain=must_not_contain,
        )

    @staticmethod
    def test_schema_hook_post_parse_attribute_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        *,
        should_succeed: bool = True,
        expected_error: str | None = None,
        validate_result: bool = True,
    ) -> FlextLdifModels.SchemaAttribute | None:
        """Complete schema hook_post_parse_attribute test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to test hook with
            should_succeed: Whether hook should succeed (default: True)
            expected_error: Optional expected error substring if should fail
            validate_result: Whether to validate returned attribute (default: True)

        Returns:
            Parsed SchemaAttribute if success, None if failure

        """
        return SchemaTestHelpers.test_hook_post_parse_attribute_complete(
            schema_quirk,
            attr,
            should_succeed=should_succeed,
            expected_error=expected_error,
            validate_result=validate_result,
        )

    @staticmethod
    def test_schema_hook_post_parse_objectclass_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        *,
        should_succeed: bool = True,
        expected_error: str | None = None,
        validate_result: bool = True,
    ) -> FlextLdifModels.SchemaObjectClass | None:
        """Complete schema hook_post_parse_objectclass test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to test hook with
            should_succeed: Whether hook should succeed (default: True)
            expected_error: Optional expected error substring if should fail
            validate_result: Whether to validate returned objectClass (default: True)

        Returns:
            Parsed SchemaObjectClass if success, None if failure

        """
        return SchemaTestHelpers.test_hook_post_parse_objectclass_complete(
            schema_quirk,
            oc,
            should_succeed=should_succeed,
            expected_error=expected_error,
            validate_result=validate_result,
        )

    @staticmethod
    def test_schema_roundtrip_attribute_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> tuple[FlextLdifModels.SchemaAttribute, str]:
        """Complete schema attribute roundtrip test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Tuple of (parsed_attribute, written_ldif_string)

        """
        return SchemaTestHelpers.test_parse_write_roundtrip_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )

    @staticmethod
    def test_schema_roundtrip_objectclass_complete(
        schema_quirk: FlextLdifServersBase.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> tuple[FlextLdifModels.SchemaObjectClass, str]:
        """Complete schema objectClass roundtrip test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Tuple of (parsed_objectClass, written_ldif_string)

        """
        return SchemaTestHelpers.test_parse_write_roundtrip_objectclass(
            schema_quirk,
            oc_def,
            expected_oid,
            expected_name,
        )


__all__ = ["QuirkTestHelpers"]
