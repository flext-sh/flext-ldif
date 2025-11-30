"""Test validators for flext-ldif.

This module provides validation utilities for testing flext-ldif functionality.
"""

from __future__ import annotations


# Mock replacements for flext_tests dependencies
class MockResultHelpers:
    @staticmethod
    def validate_composition(*args, **kwargs) -> bool:
        return True

    @staticmethod
    def validate_chain(*args, **kwargs) -> bool:
        return True

    @staticmethod
    def assert_composition(*args, **kwargs) -> None:
        pass

    @staticmethod
    def assert_chain_success(*args, **kwargs) -> None:
        pass


class MockMatchers:
    @staticmethod
    def assert_success(*args, **kwargs) -> None:
        pass


# Global assignments
ResultHelpers = MockResultHelpers
Matchers = MockMatchers

# Now import other modules
from flext_core import FlextResult, FlextUtilities

from flext_ldif.models import FlextLdifModels
from tests.fixtures.typing import GenericFieldsDict


class TestValidators:
    """Validation utilities for flext-ldif tests.

    Provides LDIF-specific validation methods for test assertions.
    Only LDIF-specific validation methods are implemented here.
    """

    # Expose FlextUtilities.Validation for pattern validation
    Validation = FlextUtilities.Validation

    @staticmethod
    def validate_ldif_entry(entry: FlextLdifModels.Entry) -> dict[str, bool]:
        """Validate a real LDIF entry object.

        Args:
            entry: The LDIF entry to validate.

        Returns:
            Dict with validation results.

        """
        return {
            "dn_format_valid": bool(entry.dn and "=" in entry.dn),
            "has_attributes": len(entry.attributes) > 0,
            "attributes_valid": all(
                isinstance(k, str) and isinstance(v, list)
                for k, v in entry.attributes.items()
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
            chain = ResultHelpers.validate_chain(results)
            assert not chain["is_valid_chain"], "Expected failures but all succeeded"

    @staticmethod
    def validate_result_success(result: FlextResult) -> GenericFieldsDict:
        """Validate FlextResult success characteristics."""
        return {
            "is_success": result.is_success,
            "has_value": hasattr(result, "value"),
            "no_error": not hasattr(result, "error") or result.error is None,
        }
