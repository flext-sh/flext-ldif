# from flext-ldif_docs/development.md:289
# Handle continuation lines
ldif_with_continuation = """dn: cn=long name that spans multiple lines,
 ou=people,dc=example,dc=com
cn: long name that spans multiple lines
"""

# Handle base64 encoded values
ldif_with_base64 = """dn: cn=user,dc=example,dc=com
cn:: dXNlcg==
"""

# Handle URL references (if enabled)
ldif_with_url = """dn: cn=user,dc=example,dc=com
photo:< file:///path/to/photo.jpg
"""```
### Memory Debugging

