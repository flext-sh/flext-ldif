"""Test validators for flext-ldif.

This module provides validation utilities for testing flext-ldif functionality.
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_core import r

from flext_ldif import m, p, t
from tests import u


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
    ) -> Mapping[str, bool | Mapping[str, t.StrSequence] | dict[str, t.StrSequence]]:
        """Validate a real LDIF entry t.NormalizedValue.

        Args:
            entry: The LDIF entry to validate.

        Returns:
            Dict with validation results.

        """
        dn_value = entry.dn if entry.dn is not None else ""
        if entry.attributes is not None:
            if isinstance(entry.attributes, m.Ldif.Attributes):
                attributes_dict: Mapping[str, t.StrSequence] = (
                    entry.attributes.attributes
                )
            else:
                attributes_dict = {}
        else:
            attributes_dict = {}
        return {
            "dn_format_valid": bool(entry.dn is not None and "=" in dn_value),
            "has_attributes": attributes_dict,
            "attributes_valid": all(
                (
                    isinstance(k, str) and isinstance(v, list)
                    for k, v in attributes_dict.items()
                ),
            ),
        }

    @staticmethod
    def validate_result_success(
        result: r[t.Ldif.NormalizedValue],
    ) -> Mapping[str, bool]:
        """Validate r success characteristics."""
        return {
            "is_success": result.is_success,
            "has_value": hasattr(result, "value"),
            "no_error": not hasattr(result, "error") or result.error is None,
        }
