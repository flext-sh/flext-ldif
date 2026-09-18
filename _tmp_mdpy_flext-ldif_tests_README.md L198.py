# from flext-ldif/tests/README.md:198
from __future__ import annotations


def test_ldif_rfc_compliance(rfc_compliant_ldif):
    """Test RFC 2849 LDIF specification compliance."""
    result = flext_ldif_parse(rfc_compliant_ldif)
    assert len(result) > 0

    # Validate specific RFC requirements
    for entry in result:
        assert str(entry.dn)  # DN is required
        assert len(str(entry.dn)) <= 255  # DN length limit
