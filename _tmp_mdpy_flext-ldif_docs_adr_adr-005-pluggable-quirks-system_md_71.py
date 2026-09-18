# from flext-ldif_docs/adr/adr-005-pluggable-quirks-system.md:71
# Auto-discovery and registration
registry = FlextLdifServer()
registry.load_alls()

# Priority-based resolution
oid = registry.get_for_server("oid")  # Priority 10
oud = registry.get_for_server("oud")  # Priority 20

# RFC-first with servers enhancement
result = rfc_parser.parse_withs(content, server, data_type="schema")```
**Consequences**:

**Positive**:

- **Extensibility**: Easy addition of new server support without core changes
- **Separation of Concerns**: Server-specific code isolated from RFC standards
- **Priority Resolution**: Handles conflicting requirements between servers
- **Type Safety**: Strong typing for all server operations
- **Testability**: Each server implementation can be tested independently

**Negative**:

- **Complexity**: Additional architectural layers and abstractions
- **Maintenance**: Each server requires separate implementation and testing
- **Performance**: Indirection through server resolution system
- **Learning Curve**: Developers must understand server system design

**Neutral**:

- **Implementation Status**: 4 complete, 5 stub implementations
- **Incremental Adoption**: New servers can be added as stubs first

**Alternatives Considered**:

1. **Conditional Logic**: Hard-coded if/else statements for each server

   - **Rejected**: Inextensible, violates OCP, hard to maintain

1. **Configuration Files**: External configuration instead of code

   - **Rejected**: Cannot handle complex server-specific logic, less type-safe

1. **Inheritance Hierarchy**: Complex inheritance instead of composition

   - **Rejected**: Tightly coupled, harder to test and maintain

**Related ADRs**:

- ADR-001 - RFC foundation that servers enhance
- ADR-002 - Uses servers for conversions

**Notes**:
The pluggable servers system enables FLEXT-LDIF's multi-server support while maintaining clean architecture. Each server gets its own module with complete implementation isolation. The priority system allows fine-tuned control over how different server requirements are resolved.

**Current Implementation Status**:

- ✅ **Complete Implementations**: OID, OUD, OpenLDAP 1.x/2.x (4 servers)
- ⚠️ **Stub Implementations**: AD, Apache DS, 389 DS, Novell, Tivoli (5 servers)
- 🔄 **Future Enhancement**: Convert stubs to full implementations based on user requirements

**Architecture Benefits**:

- **Zero Core Changes**: Adding new servers doesn't modify existing code
- **Independent Testing**: Each server implementation tested separately
- **Version Compatibility**: Server servers can be versioned independently
- **Graceful Degradation**: Stubs allow framework to recognize servers even without full implementation
