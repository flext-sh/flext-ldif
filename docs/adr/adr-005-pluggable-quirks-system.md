# ADR-005: Pluggable Quirks System


<!-- TOC START -->
- No sections found
<!-- TOC END -->

**Status**: Accepted

**Date**: 2025-10-10

**Context**:
LDAP servers implement the RFC standards differently, requiring server-specific adaptations. FLEXT-LDIF must support 9+ LDAP server implementations while maintaining a clean, extensible architecture.

Server-specific requirements include:

- **OID**: Oracle-specific schema extensions and operational attributes
- **OUD**: Case-sensitive DN handling and nested ACL/entry quirks
- **OpenLDAP**: Custom OID ranges and operational attributes
- **Active Directory**: Required object classes and attribute handling
- **Apache DS**: Validation rules and schema extensions
- **389 DS**: Red Hat specific operational attributes
- **Novell eDirectory**: Legacy compatibility features
- **IBM Tivoli DS**: Enterprise-specific extensions

The challenge was creating an architecture that could:

- Support multiple server implementations without code duplication
- Allow easy addition of new server support
- Maintain clean separation between RFC standards and server extensions
- Provide priority-based resolution for conflicting server requirements

**Decision**:
Implement a **pluggable quirks system** with:

1. **QuirkBase abstract class** defining standard interfaces
2. **Auto-discovery registry** for loading quirk implementations
3. **Priority-based resolution** for handling conflicts
4. **Nested quirk architecture** (Schema + ACL + Entry quirks)
5. **Integration with RFC-first design** as enhancement layer

**Key Components**:

```python
class QuirkBase(ABC):
    """Base class for server-specific quirk implementations."""

    @property
    @abstractmethod
    def server_name(self) -> str:
        """Server identifier."""

    @property
    @abstractmethod
    def priority(self) -> int:
        """Resolution priority (lower = higher priority)."""

    @abstractmethod
    def to_rfc(self, data: str, data_type: str) -> FlextResult[str]:
        """Convert server format to RFC standard."""

    @abstractmethod
    def from_rfc(self, data: str, data_type: str) -> FlextResult[str]:
        """Convert RFC standard to server format."""
```

**Implementation**:

```python
# Auto-discovery and registration
registry = FlextLdifServer()
registry.load_alls()

# Priority-based resolution
oid = registry.get_for_server("oid")  # Priority 10
oud = registry.get_for_server("oud")  # Priority 20

# RFC-first with quirks enhancement
result = rfc_parser.parse_withs(
    content, server, data_type="schema"
)
```

**Consequences**:

**Positive**:

- **Extensibility**: Easy addition of new server support without core changes
- **Separation of Concerns**: Server-specific code isolated from RFC standards
- **Priority Resolution**: Handles conflicting requirements between servers
- **Type Safety**: Strong typing for all quirk operations
- **Testability**: Each server implementation can be tested independently

**Negative**:

- **Complexity**: Additional architectural layers and abstractions
- **Maintenance**: Each server requires separate implementation and testing
- **Performance**: Indirection through quirk resolution system
- **Learning Curve**: Developers must understand quirk system design

**Neutral**:

- **Implementation Status**: 4 complete, 5 stub implementations
- **Incremental Adoption**: New servers can be added as stubs first

**Alternatives Considered**:

1. **Conditional Logic**: Hard-coded if/else statements for each server
   - **Rejected**: Inextensible, violates OCP, hard to maintain

2. **Configuration Files**: External configuration instead of code
   - **Rejected**: Cannot handle complex server-specific logic, less type-safe

3. **Inheritance Hierarchy**: Complex inheritance instead of composition
   - **Rejected**: Tightly coupled, harder to test and maintain

**Related ADRs**:

- [ADR-001](adr-001-rfc-first-design.md) - RFC foundation that quirks enhance
- [ADR-002](adr-002-universal-conversion-matrix.md) - Uses quirks for conversions

**Notes**:
The pluggable quirks system enables FLEXT-LDIF's multi-server support while maintaining clean architecture. Each server gets its own module with complete implementation isolation. The priority system allows fine-tuned control over how different server requirements are resolved.

**Current Implementation Status**:

- ✅ **Complete Implementations**: OID, OUD, OpenLDAP 1.x/2.x (4 servers)
- ⚠️ **Stub Implementations**: AD, Apache DS, 389 DS, Novell, Tivoli (5 servers)
- 🔄 **Future Enhancement**: Convert stubs to full implementations based on user requirements

**Architecture Benefits**:

- **Zero Core Changes**: Adding new servers doesn't modify existing code
- **Independent Testing**: Each server implementation tested separately
- **Version Compatibility**: Server quirks can be versioned independently
- **Graceful Degradation**: Stubs allow framework to recognize servers even without full implementation
