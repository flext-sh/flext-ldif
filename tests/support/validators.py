"""Test validators for flext-ldif.

This module provides validation utilities for testing flext-ldif functionality.
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_core import r

from tests import p, t, u


class MockFlextUtilitiesResultHelpers:
    """Mock result helpers for testing."""

    @staticmethod
    def validate_composition(*args: t.Scalar, **kwargs: t.Scalar) -> bool:
        """Validate composition."""
        return True

    @staticmethod
    def validate_chain(*args: t.Scalar, **kwargs: t.Scalar) -> bool:
        """Validate chain."""
        return True

    @staticmethod
    def assert_composition(*args: t.Scalar, **kwargs: t.Scalar) -> None:
        """Assert composition."""

    @staticmethod
    def assert_chain_success(*args: t.Scalar, **kwargs: t.Scalar) -> None:
        """Assert chain success."""


class MockMatchers:
    """Mock matchers for testing."""

    @staticmethod
    def assert_success(*args: t.Scalar, **kwargs: t.Scalar) -> None:
        """Assert success."""


class TestValidators:
    """Validation utilities for flext-ldif tests.

    Provides LDIF-specific validation methods for test assertions.
    Only LDIF-specific validation methods are implemented here.
    """

    Validation = u

    @staticmethod
    def validate_ldif_entry(
        entry: p.Entry,
    ) -> Mapping[str, bool]:
        """Validate a real LDIF entry t.NormalizedValue.

        Args:
            entry: The LDIF entry to validate.

        Returns:
            Dict with validation results.

        """
        dn_value: str = entry.dn
        attributes_dict: Mapping[str, t.StrSequence] = entry.attributes
        return {
            "dn_format_valid": bool("=" in dn_value),
            "has_attributes": bool(attributes_dict),
            "attributes_valid": bool(attributes_dict),
        }

    @staticmethod
    def validate_result_success(
        result: r[t.Ldif.RecursiveContainer],
    ) -> Mapping[str, bool]:
        """Validate r success characteristics."""
        return {
            "is_success": result.is_success,
            "has_value": hasattr(result, "value"),
            "no_error": not hasattr(result, "error") or result.error is None,
        }
