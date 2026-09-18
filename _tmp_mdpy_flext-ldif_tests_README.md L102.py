# from flext-ldif/tests/README.md:102
from __future__ import annotations


def test_flext_ldif_entry_validation(sample_entry):
    """Test domain entity validation rules."""
    entry = sample_entry
    result = entry.validate_business_rules()  # Should succeed
    assert result.is_success

    # Test business rule violations
    invalid_entry = FlextLdifModels.Entry(dn="", attributes={})
    with pytest.raises(FlextLdifValidationError):
        result = invalid_entry.validate_business_rules()
        assert not result.is_success
