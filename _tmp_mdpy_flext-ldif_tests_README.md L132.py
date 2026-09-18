# from flext-ldif/tests/README.md:132
from __future__ import annotations


def test_api_service_integration(flext_ldif_api, sample_ldif_content):
    """Test API service with real dependencies."""
    result = flext_ldif_api.parse(sample_ldif_content)
    assert result.is_success

    validation_result = flext_ldif_api.validate(result.value)
    assert validation_result.is_success
