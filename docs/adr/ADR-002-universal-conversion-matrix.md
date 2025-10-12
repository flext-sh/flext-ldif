# ADR-002: Universal Conversion Matrix Architecture

**Status**: Accepted

**Date**: 2025-10-10

**Context**:
FLEXT-LDIF supports 9+ LDAP server implementations (OID, OUD, OpenLDAP, Active Directory, etc.), each with different syntax requirements and quirks. The challenge was providing seamless conversion between any server pair without implementing N×N conversion functions.

Traditional approaches would require:
- OID → OUD conversion function
- OID → OpenLDAP conversion function
- OUD → OpenLDAP conversion function
- And so on... resulting in O(n²) implementations

We needed a scalable architecture that could support any-to-any server conversion with minimal implementation effort.

**Decision**:
Implement a **Universal Conversion Matrix** using RFC standards as intermediate representation:

**Conversion Pattern**:
```
Source Format → Source.to_rfc() → RFC Format → Target.from_rfc() → Target Format
```

**Key Components**:
1. **QuirksConversionMatrix**: Facade providing N×N conversion interface
2. **DnCaseRegistry**: Tracks canonical DN case for OUD compatibility
3. **QuirkBase Interface**: Defines `to_rfc()` and `from_rfc()` methods
4. **RFC Intermediate Format**: Standards-compliant representation

**Implementation**:
```python
# N×N conversion with only 2×N implementations
matrix = QuirksConversionMatrix()

# Convert between any server combination
result = matrix.convert(
    source_quirk=oud_quirk,
    target_quirk=oid_quirk,
    data_type="attribute",
    data=oud_attribute_string
)
```

**Consequences**:

**Positive**:
- **Scalability**: Convert between any server pair with minimal new code
- **Standards-Based**: RFC compliance ensures interoperability
- **Maintainability**: Clear separation of concerns per server
- **Extensibility**: Easy addition of new server support
- **Consistency**: All conversions follow the same pipeline

**Negative**:
- **Complexity**: Additional architectural layers and abstractions
- **Performance**: Multiple conversion steps (Source → RFC → Target)
- **Memory Usage**: RFC intermediate representation requires additional memory
- **Debugging**: More complex call stacks for troubleshooting

**Neutral**:
- **Implementation Cost**: Only 2 methods needed per server (to_rfc, from_rfc)
- **Testing**: Each server needs comprehensive RFC conversion tests

**Alternatives Considered**:

1. **Direct Server-to-Server Conversions**: Implement each conversion pair directly
   - **Rejected**: O(n²) implementations, exponential complexity

2. **Common Intermediate Format**: Use custom format instead of RFC
   - **Rejected**: Would create proprietary standard, reduce interoperability

3. **Runtime Translation Rules**: Configuration-driven translation instead of code
   - **Rejected**: Less type-safe, harder to handle complex server-specific logic

**Related ADRs**:
- [ADR-001](ADR-001-rfc-first-design.md) - RFC-first foundation
- [ADR-003](ADR-003-dn-case-registry.md) - DN case handling
- [ADR-005](ADR-005-pluggable-quirks-system.md) - Server quirk implementations

**Notes**:
The universal conversion matrix is a key innovation enabling FLEXT-LDIF's server migration capabilities. It reduces implementation complexity from O(n²) to O(n) while maintaining standards compliance. The DN case registry integration ensures OUD compatibility during conversions.

**Implementation Status**:
- ✅ Core matrix architecture implemented
- ✅ DN case registry integrated
- ✅ 4 complete server implementations (OID, OUD, OpenLDAP 1.x/2.x)
- ✅ 5 stub implementations ready for enhancement
- ⚠️ Performance optimization needed for large-scale migrations