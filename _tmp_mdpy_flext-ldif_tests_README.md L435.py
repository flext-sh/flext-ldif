# from flext-ldif/tests/README.md:435
from __future__ import annotations


def test_new_feature_specification():
    """Test specification for new feature (TDD)."""
    # Arrange - Set up test conditions
    api = ldif()
    test_data = create_test_ldif()

    # Act - Execute the feature
    result = api.new_feature(test_data)

    # Assert - Validate expected behavior
    assert result.is_success
    assert result.value.meets_requirements()
