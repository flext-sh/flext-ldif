# ADR-003: DN Case Registry for OUD Compatibility

**Status**: Accepted

**Date**: 2025-10-10

**Context**:
Different LDAP servers handle Distinguished Name (DN) case sensitivity differently:

- **OID (Oracle Internet Directory)**: Case-insensitive DNs
- **OUD (Oracle Unified Directory)**: Case-sensitive DNs with strict consistency requirements
- **OpenLDAP**: Mixed case handling depending on configuration
- **Active Directory**: Case-insensitive but preserves original case

When migrating between servers (e.g., OID → OUD), DN references in entries, ACLs, and group memberships must maintain consistent case. Without proper case management, OUD operations would fail due to case mismatches.

The challenge was tracking canonical DN case during conversions while ensuring OUD compatibility.

**Decision**:
Implement a **DN Case Registry** that:

1. **Tracks canonical case** for each normalized DN during conversion
2. **Ensures consistency** across all DN references in migrated data
3. **Validates OUD compatibility** by detecting case conflicts
4. **Integrates with conversion matrix** for seamless operation

**Key Components**:
```python
class DnCaseRegistry:
    """Tracks canonical DN case for migration consistency."""

    def register_dn(self, dn: str) -> str:
        """Register DN and return canonical case (first-seen wins)."""

    def get_canonical_dn(self, dn: str) -> str:
        """Get canonical case for any DN variant."""

    def validate_oud_consistency(self) -> FlextCore.Result[bool]:
        """Validate no case conflicts exist for OUD compatibility."""
```

**Implementation**:
```python
# During conversion pipeline
registry = DnCaseRegistry()

# Register DNs as they're encountered
canonical_dn = registry.register_dn("CN=Admin,DC=Example,DC=Com")
# Returns: "cn=admin,dc=example,dc=com"

# All subsequent references use canonical case
canonical_ref = registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
# Returns: "cn=admin,dc=example,dc=com"

# Validate for OUD deployment
result = registry.validate_oud_consistency()
```

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

2. **Case-Insensitive Storage**: Store all DNs in lowercase
   - **Rejected**: Loses original case information needed for some servers

3. **Runtime Case Resolution**: Resolve case conflicts during OUD operations
   - **Rejected**: Would cause runtime failures and poor user experience

**Related ADRs**:
- [ADR-002](ADR-002-universal-conversion-matrix.md) - Integration with conversion pipeline
- [ADR-004](ADR-004-memory-bound-architecture.md) - Memory usage implications

**Notes**:
The DN case registry is critical for OUD migrations from case-insensitive sources like OID. It ensures that all DN references in migrated data use consistent case, preventing the runtime failures that would occur in OUD's case-sensitive environment.

**Implementation Details**:
- Uses normalized DN (lowercase, no spaces) as registry keys
- First-seen DN establishes canonical case for all variants
- Integrated into universal conversion matrix pipeline
- Provides validation for OUD deployment readiness
