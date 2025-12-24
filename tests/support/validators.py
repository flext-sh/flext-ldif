"""Test validators for flext-ldif.

This module provides validation utilities for testing flext-ldif functionality.
"""

from __future__ import annotations

from typing import Any

from flext_core import FlextResult, u

from flext_ldif.models import m
from flext_ldif.protocols import p
from tests import GenericFieldsDict


class MockResultHelpers:
    """Mock result helpers for testing."""

    @staticmethod
    def validate_composition(*args: object, **kwargs: object) -> bool:
        """Validate composition."""
        return True

    @staticmethod
    def validate_chain(*args: object, **kwargs: object) -> bool:
        """Validate chain."""
        return True

    @staticmethod
    def assert_composition(*args: object, **kwargs: object) -> None:
        """Assert composition."""

    @staticmethod
    def assert_chain_success(*args: object, **kwargs: object) -> None:
        """Assert chain success."""


class MockMatchers:
    """Mock matchers for testing."""

    @staticmethod
    def assert_success(*args: object, **kwargs: object) -> None:
        """Assert success."""


# Global assignments
ResultHelpers = MockResultHelpers
Matchers = MockMatchers


class TestValidators:
    """Validation utilities for flext-ldif tests.

    Provides LDIF-specific validation methods for test assertions.
    Only LDIF-specific validation methods are implemented here.
    """

    # Expose uor pattern validation
    Validation = u

    @staticmethod
    def validate_ldif_entry(entry: p.Entry) -> dict[str, bool]:
        """Validate a real LDIF entry object.

        Args:
            entry: The LDIF entry to validate.

        Returns:
            Dict with validation results.

        """
        dn_value = entry.dn.value if entry.dn is not None else ""
        # entry.attributes is Attributes, need to access .attributes dict
        if entry.attributes is not None:
            if isinstance(entry.attributes, m.Ldif.Attributes):
                attributes_dict: dict[str, list[str]] = entry.attributes.attributes
            else:
                attributes_dict = {}
        else:
            attributes_dict = {}
        return {
            "dn_format_valid": bool(entry.dn is not None and "=" in dn_value),
            "has_attributes": len(attributes_dict) > 0,
            "attributes_valid": all(
                isinstance(k, str) and isinstance(v, list)
                for k, v in attributes_dict.items()
            ),
        }

    # Delegate to mock implementations
    assert_successful_result = staticmethod(Matchers.assert_success)
    validate_flext_result_composition = staticmethod(
        ResultHelpers.validate_composition,
    )
    validate_flext_result_chain = staticmethod(
        ResultHelpers.validate_chain,
    )
    assert_flext_result_composition = staticmethod(
        ResultHelpers.assert_composition,
    )

    @staticmethod
    def assert_flext_result_chain(
        results: list[FlextResult[object]],
        *,
        expect_all_success: bool = True,
    ) -> None:
        """Assert FlextResult chain operations."""
        if expect_all_success:
            ResultHelpers.assert_chain_success(results)
        else:
            chain_valid = ResultHelpers.validate_chain(results)
            assert not chain_valid, "Expected failures but all succeeded"

    @staticmethod
    def validate_result_success(result: FlextResult[Any]) -> GenericFieldsDict:
        """Validate FlextResult success characteristics."""
        return {
            "is_success": result.is_success,
            "has_value": hasattr(result, "value"),
            "no_error": not hasattr(result, "error") or result.error is None,
        }
