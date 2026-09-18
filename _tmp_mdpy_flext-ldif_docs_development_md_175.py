# from flext-ldif_docs/development.md:175
from __future__ import annotations


# Create test LDIF content
def create_test_ldif() -> str:
    """Create valid LDIF content for testing."""
    return """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: organizationalPerson
mail: test@example.com

dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
cn: REDACTED_LDAP_BIND_PASSWORD
objectClass: person
description: Administrator account
"""


# Test parsing with various LDIF formats
def test_ldif_parsing():
    api = ldif()
    result = api.parse_string(create_test_ldif())
    assert result.success
    entries = result.unwrap()
    assert len(entries) == 2```
### Memory Usage Testing

