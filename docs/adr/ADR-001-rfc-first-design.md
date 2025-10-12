# ADR-001: RFC-First Design with Zero Bypass Paths

**Status**: Accepted

**Date**: 2025-10-10

**Context**:
FLEXT-LDIF processes LDAP Data Interchange Format (LDIF) files for multiple LDAP server implementations. The challenge was ensuring standards compliance while supporting server-specific extensions without compromising architectural integrity.

The system needed to:

- Maintain strict RFC 2849 (LDIF) and RFC 4512 (Schema) compliance
- Support 9+ different LDAP server implementations with varying quirks
- Provide a consistent, maintainable architecture for current and future server support
- Prevent direct access to internal parsers that could bypass standards compliance

**Decision**:
Implement a **RFC-First Design with Zero Bypass Paths** where:

1. **All parsing operations MUST go through RFC-compliant parsers first**
2. **Server-specific quirks are applied as enhancements on top of RFC baseline**
3. **No direct access to parsers** - all operations route through the facade
4. **Mandatory quirk_registry parameter** for all RFC parser operations
5. **CQRS pattern** separates parsing from writing operations

**Key Implementation**:

```python
# RFC parsers always receive quirk_registry
parser = RfcLdifParserService(
    params={"file_path": "data.ldif"},
    quirk_registry=quirk_registry,  # MANDATORY
    server_type="oid"  # Applied as enhancement
)

# All operations through facade
ldif = FlextLdif()
result = ldif.parse(file_path)  # No direct parser access
```

**Consequences**:

**Positive**:

- **Standards Compliance**: Guaranteed RFC adherence for all operations
- **Architectural Integrity**: Clear separation between standards and extensions
- **Maintainability**: Easy to add new server support without core changes
- **Consistency**: All code paths follow the same RFC → Quirks pipeline
- **Testability**: Clear boundaries between RFC compliance and server extensions

**Negative**:

- **Development Overhead**: All operations must route through facade layers
- **Performance Impact**: Additional indirection through CQRS handlers
- **Complexity**: More architectural layers to understand and maintain

**Neutral**:

- **Learning Curve**: Developers must understand RFC-first philosophy
- **Code Volume**: More classes and interfaces for architectural separation

**Alternatives Considered**:

1. **Direct Parser Access**: Allow direct use of parsers with optional quirks
   - **Rejected**: Would compromise standards compliance and create bypass paths

2. **Server-Specific Parsers**: Separate parsers for each LDAP server
   - **Rejected**: Would duplicate RFC logic and complicate maintenance

3. **Configuration-Driven Extensions**: Runtime configuration instead of code
   - **Rejected**: Less type-safe and harder to test server-specific logic

**Related ADRs**:

- [ADR-005](ADR-005-pluggable-quirks-system.md) - Implementation details of quirks system

**Notes**:
This decision establishes the fundamental architectural pattern for FLEXT-LDIF. All subsequent development must maintain the RFC-first principle and zero bypass paths constraint. The facade pattern ensures consistent application of this principle across all operations.
