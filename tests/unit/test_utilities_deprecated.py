"""Tests for deprecated utilities.py module.

This module tests the deprecated utilities.py file to ensure it maintains
backward compatibility during the transition period.
"""

from __future__ import annotations


def test_utilities_import() -> None:
    """Test that deprecated utilities module can be imported."""
    # Import should succeed with empty __all__
    import flext_ldif.utilities

    assert hasattr(flext_ldif.utilities, "__all__")
    assert flext_ldif.utilities.__all__ == []


def test_utilities_all_empty() -> None:
    """Test that __all__ is empty as expected."""
    from flext_ldif import utilities

    assert utilities.__all__ == []
    assert len(utilities.__all__) == 0
