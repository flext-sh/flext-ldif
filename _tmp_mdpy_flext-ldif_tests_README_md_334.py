# from flext-ldif_tests/README.md:334
from __future__ import annotations


def generate_ldif_with_entries(count: int) -> str:
    """Generate LDIF content with specified number of entries."""
    entries = []
    for i in range(count):
        entry = f"""
dn: cn=user{i:05d},ou=people,dc=example,dc=com
cn: user{i:05d}
objectClass: person
objectClass: inetOrgPerson
mail: user{i:05d}@example.com
uid: user{i:05d}
"""
        entries.append(entry.strip())

    return "\n\n".join(entries)
