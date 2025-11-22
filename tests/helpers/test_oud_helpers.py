"""OUD test helpers.

High-level OUD test helpers that replace entire test functions.
All helpers use real implementations with real data, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.servers.oud import FlextLdifServersOud

from .test_assertions import TestAssertions


class OudTestHelpers:
    """High-level OUD test helpers that replace entire test functions."""

    @staticmethod
    def test_schema_parse_attribute(
        schema_quirk: FlextLdifServersOud.Schema,
        attr_def: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Complete schema attribute parse test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Returns:
            Parsed SchemaAttribute

        """
        result = schema_quirk.parse(attr_def)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "Attribute parse should succeed",
        )
        attr = cast("FlextLdifModels.SchemaAttribute", unwrapped)
        assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
            "Parse should return SchemaAttribute"
        )
        if expected_oid is not None:
            assert attr.oid == expected_oid, (
                f"Expected OID {expected_oid}, got {attr.oid}"
            )
        if expected_name is not None:
            assert attr.name == expected_name, (
                f"Expected name {expected_name}, got {attr.name}"
            )
        TestAssertions.assert_schema_attribute_valid(
            attr,
            expected_oid or "",
            expected_name or "",
        )
        return attr

    @staticmethod
    def test_schema_parse_objectclass(
        schema_quirk: FlextLdifServersOud.Schema,
        oc_def: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Complete schema objectClass parse test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Returns:
            Parsed SchemaObjectClass

        """
        result = schema_quirk.parse(oc_def)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "ObjectClass parse should succeed",
        )
        oc = cast("FlextLdifModels.SchemaObjectClass", unwrapped)
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass), (
            "Parse should return SchemaObjectClass"
        )
        if expected_oid is not None:
            assert oc.oid == expected_oid, f"Expected OID {expected_oid}, got {oc.oid}"
        if expected_name is not None:
            assert oc.name == expected_name, (
                f"Expected name {expected_name}, got {oc.name}"
            )
        TestAssertions.assert_schema_objectclass_valid(
            oc,
            expected_oid or "",
            expected_name or "",
        )
        return oc

    @staticmethod
    def test_schema_write_attribute(
        schema_quirk: FlextLdifServersOud.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        must_contain: list[str] | None = None,
    ) -> str:
        """Complete schema attribute write test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to write
            must_contain: Optional list of strings that must be in written output

        Returns:
            Written attribute definition string

        """
        result = schema_quirk.write(attr)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "Attribute write should succeed",
        )
        written = cast("str", unwrapped)
        assert isinstance(written, str), "Write should return string"
        assert len(written) > 0, "Written string should not be empty"

        if must_contain is not None:
            for required_str in must_contain:
                assert required_str in written, (
                    f"Written output must contain '{required_str}'"
                )

        return written

    @staticmethod
    def test_schema_write_objectclass(
        schema_quirk: FlextLdifServersOud.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        must_contain: list[str] | None = None,
    ) -> str:
        """Complete schema objectClass write test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to write
            must_contain: Optional list of strings that must be in written output

        Returns:
            Written objectClass definition string

        """
        result = schema_quirk.write(oc)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "ObjectClass write should succeed",
        )
        written = cast("str", unwrapped)
        assert isinstance(written, str), "Write should return string"
        assert len(written) > 0, "Written string should not be empty"

        if must_contain is not None:
            for required_str in must_contain:
                assert required_str in written, (
                    f"Written output must contain '{required_str}'"
                )

        return written

    @staticmethod
    def test_acl_quirk_parse(
        acl_quirk: FlextLdifServersOud.Acl,
        acl_line: str,
        expected_raw_acl: str | None = None,
    ) -> FlextLdifModels.Acl:
        """Complete ACL quirk parse test - replaces entire test function.

        Args:
            acl_quirk: ACL quirk instance
            acl_line: ACL line string to parse
            expected_raw_acl: Optional expected raw ACL value

        Returns:
            Parsed Acl model

        """
        result = acl_quirk.parse(acl_line)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "ACL parse should succeed",
        )
        acl = cast("FlextLdifModels.Acl", unwrapped)
        assert isinstance(acl, FlextLdifModels.Acl), "Parse should return Acl"
        if expected_raw_acl is not None:
            assert acl.raw_acl == expected_raw_acl, (
                f"Expected raw_acl {expected_raw_acl}, got {acl.raw_acl}"
            )
        return acl

    @staticmethod
    def test_acl_quirk_write(
        acl_quirk: FlextLdifServersOud.Acl,
        acl: FlextLdifModels.Acl,
        expected_content: str | None = None,
    ) -> str:
        """Complete ACL quirk write test - replaces entire test function.

        Args:
            acl_quirk: ACL quirk instance
            acl: Acl model to write
            expected_content: Optional expected content in written output

        Returns:
            Written ACL string

        """
        result = acl_quirk.write(acl)
        unwrapped = TestAssertions.assert_success(
            cast("FlextResult[object]", result),
            "ACL write should succeed",
        )
        written = cast("str", unwrapped)
        assert isinstance(written, str), "Write should return string"

        if expected_content is not None:
            assert expected_content in written, (
                f"Written output must contain '{expected_content}'"
            )

        return written
