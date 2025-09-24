"""Comprehensive tests for FlextLdifModels to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_ldif import FlextLdifModels


class TestDistinguishedNameExceptionHandling:
    """Tests for DistinguishedName exception handling."""

    def test_create_dn_generic_exception_coverage(self) -> None:
        """Test create_dn with generic Exception (lines 63-66)."""
        with patch.object(
            FlextLdifModels.DistinguishedName,
            "__init__",
            side_effect=RuntimeError("Unexpected error"),
        ):
            result = FlextLdifModels.DistinguishedName.create(
                "cn=test,dc=example,dc=com"
            )

            assert result.is_failure
            assert result.error is not None
            error_msg = result.error
            assert error_msg and "DN creation error" in error_msg
            assert error_msg and "Unexpected error" in error_msg


class TestLdifAttributesValidation:
    """Tests for LdifAttributes validation."""

    def test_create_ldif_attributes_generic_exception_coverage(self) -> None:
        """Test create_ldif_attributes with generic Exception (lines 125-128)."""
        with patch.object(
            FlextLdifModels.LdifAttributes,
            "__init__",
            side_effect=RuntimeError("Unexpected error"),
        ):
            result = FlextLdifModels.LdifAttributes.create({"cn": ["test"]})

            assert result.is_failure
            assert result.error is not None
            error_msg = result.error
            assert error_msg and "attributes creation error" in error_msg
            assert error_msg and "Unexpected error" in error_msg


class TestLdifUrlExceptionHandling:
    """Tests for LdifUrl exception handling."""

    def test_create_ldif_url_generic_exception_coverage(self) -> None:
        """Test create_ldif_url with generic Exception (lines 245-248)."""
        with patch.object(
            FlextLdifModels.LdifUrl,
            "__init__",
            side_effect=RuntimeError("Unexpected error"),
        ):
            result = FlextLdifModels.LdifUrl.create("file:///path/to/file.ldif")

            assert result.is_failure
            assert result.error is not None
            error_msg = result.error
            assert error_msg and "URL creation error" in error_msg
            assert error_msg and "Unexpected error" in error_msg
