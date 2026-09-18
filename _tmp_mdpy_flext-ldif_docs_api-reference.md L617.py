# from flext-ldif/docs/api-reference.md:617
from flext_ldif import FlextLdifModels

# Create entries directly with the public Entry model
person = FlextLdifModels.Entry(
    dn="cn=John Doe,ou=People,dc=example,dc=com",
    attributes={"cn": ["John Doe"], "sn": ["Doe"], "mail": ["john.doe@example.com"]},
)

group = FlextLdifModels.Entry(
    dn="cn=Admins,ou=Groups,dc=example,dc=com",
    attributes={
        "cn": ["Administrators"],
        "member": ["cn=John Doe,ou=People,dc=example,dc=com"],
    },
)```
## Configuration Management

### Global Configuration

