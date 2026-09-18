# from flext-ldif_examples/README.md:201
from flext_ldif import ldif

# Initialize API
api = ldif()

# Use functionality
result = api.parse_string("dn: cn=test,dc=example,dc=com\ncn: test\n")

if result.is_success:
    entries = result.unwrap()
    # Process entries
else:
    error = result.error
    # Handle error
