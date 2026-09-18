# from flext-ldif_docs/api-reference.md:1193
from flext_ldif import ldif

ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: inetOrgPerson
cn: test"""

api = ldif()
result = api.parse_string(ldif_content)
if result.success:
    entries = result.unwrap()
    u.Cli.print(f"✅ Parsed {len(entries)} entries")
else:
    u.Cli.print(f"❌ Failed to parse LDIF: {result.error}")```
### Generic Migration Pipeline

