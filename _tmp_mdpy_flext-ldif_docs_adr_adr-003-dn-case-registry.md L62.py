# from flext-ldif/docs/adr/adr-003-dn-case-registry.md:62
from __future__ import annotations


class DnCaseRegistry:
    def register_dn(self, dn: str) -> str:
        return dn.lower()

    def get_canonical_dn(self, dn: str) -> str:
        return dn.lower()

    def validate_oud_consistency(self) -> bool:
        return True


# During conversion pipeline
registry = DnCaseRegistry()

# Register DNs as they're encountered
canonical_dn = registry.register_dn("CN=Admin,DC=Example,DC=Com")
# Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

# All subsequent references use canonical case
canonical_ref = registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
# Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

# Validate for OUD deployment
result = registry.validate_oud_consistency()```
**Consequences**:

**Positive**:

- **OUD Compatibility**: Ensures consistent DN case for case-sensitive operations
- **Migration Safety**: Prevents runtime failures due to case mismatches
- **Automatic Resolution**: No manual DN case management required
- **Conflict Detection**: Identifies case inconsistencies before deployment
- **Standards Compliant**: Works with RFC 4514 DN syntax rules

**Negative**:

- **Memory Overhead**: Maintains DN registry during conversion
- **Processing Overhead**: Additional lookups during conversion pipeline
- **State Management**: Must track registry state across conversion operations
- **Complexity**: Additional architectural component to maintain

**Neutral**:

- **First-Seen-Wins Policy**: Simple, predictable case resolution
- **Normalized Storage**: Efficient DN comparison using case-insensitive keys

**Alternatives Considered**:

1. **Manual DN Case Management**: Require users to specify canonical case

   - **Rejected**: Error-prone, requires domain expertise, not scalable

1. **Case-Insensitive Storage**: Store all DNs in lowercase

   - **Rejected**: Loses original case information needed for some servers

1. **Runtime Case Resolution**: Resolve case conflicts during OUD operations

   - **Rejected**: Would cause runtime failures and poor user experience

**Related ADRs**:

- ADR-002 - Integration with conversion pipeline
- ADR-004 - Memory usage implications

**Notes**:
The DN case registry is critical for OUD migrations from case-insensitive sources like OID. It ensures that all DN references in migrated data use consistent case, preventing the runtime failures that would occur in OUD's case-sensitive environment.

**Implementation Details**:

- Uses normalized DN (lowercase, no spaces) as registry keys
- First-seen DN establishes canonical case for all variants
- Integrated into universal conversion matrix pipeline
- Provides validation for OUD deployment readiness
