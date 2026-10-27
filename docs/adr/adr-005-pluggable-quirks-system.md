# ADR-005: Pluggable Servers System

<!-- TOC START -->

- [Amendment 2026-10-25: servers by dependency injection only](#amendment-2026-10-25-servers-by-dependency-injection-only)
- [Amendment 2026-10-25: capability composition](#amendment-2026-10-25-capability-composition)

<!-- TOC END -->

**Status**: Accepted; registry and priority resolution superseded on 2026-10-25 (see
the amendments at the end)

**Date**: 2026-04-14

**Context**: LDAP servers implement the RFC standards differently, requiring
server-specific adaptations. FLEXT-LDIF must support 9+ LDAP server implementations
while maintaining a clean, extensible architecture.

Server-specific requirements include:

- **OID**: Oracle-specific schema extensions and operational attributes
- **OUD**: Case-sensitive DN handling and nested ACL/entry servers
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

**Decision**: Implement a **pluggable servers system** with:

1. **ServerBase abstract class** defining standard interfaces
1. **Auto-discovery registry** for loading server implementations
1. **Priority-based resolution** for handling conflicts
1. **Nested server architecture** (Schema + ACL + Entry servers)
1. **Integration with RFC-first design** as enhancement layer

**Key Components**:

from **future** import annotations
from abc import ABC
from abc import abstractmethod
from flext_ldif import p

class ServerBase(ABC):
"""Base class for server-specific server implementations."""

    @property
    @abstractmethod
    def server_name(self) -> str:
        """Server identifier."""

    @property
    @abstractmethod
    def priority(self) -> int:
        """Resolution priority (lower = higher priority)."""

    @abstractmethod
    def to_rfc(self, data: str, data_type: str) -> p.Result[str]:
        """Convert server format to RFC standard."""

    @abstractmethod
    def from_rfc(self, data: str, data_type: str) -> p.Result[str]:
        """Convert RFC standard to server format."""

**Implementation**:

```text
# Auto-discovery and registration
registry = FlextLdifServer()
registry.load_alls()

# Priority-based resolution
oid = registry.get_for_server("oid")  # Priority 10
oud = registry.get_for_server("oud")  # Priority 20

# RFC-first with servers enhancement
result = rfc_parser.parse_withs(content, server, data_type="schema")
```

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

**Notes**: The pluggable servers system enables FLEXT-LDIF's multi-server support while
maintaining clean architecture. Each server gets its own module with complete
implementation isolation. The priority system allows fine-tuned control over how
different server requirements are resolved.

**Current Implementation Status**:

- ✅ **Complete Implementations**: OID, OUD, OpenLDAP 1.x/2.x (4 servers)
- ⚠️ **Stub Implementations**: AD, Apache DS, 389 DS, Novell, Tivoli (5 servers)
- 🔄 **Future Enhancement**: Convert stubs to full implementations based on user
  requirements

**Architecture Benefits**:

- **Zero Core Changes**: Adding new servers doesn't modify existing code
- **Independent Testing**: Each server implementation tested separately
- **Version Compatibility**: Server servers can be versioned independently
- **Graceful Degradation**: Stubs allow framework to recognize servers even without full
  implementation

## Amendment 2026-10-25: servers by dependency injection only

Operator order of 2026-10-25 supersedes the auto-discovery registry, the priority-based
resolution and every lookup of a server by name above:

- LDIF and LDAP servers are used only through dependency injection. No registry, no
  lookup by server type and no ready-made list of servers selects a dialect.
- Services, and the `c`, `t`, `p`, `m` and `u` facades, never know which server they
  use. They depend on `p.Ldif` protocols received as typed ports; the composition root
  alone chooses and constructs the concrete dialect.
- The facades and services understand only RFC LDIF, its extensions and metadata.
  They declare no dialect name, enumeration, constant, model, utility or branch for
  OID, OUD, OpenLDAP or any other dialect. Each dialect owns its own constants and
  logic inside its server package and translates between its format and the neutral
  RFC + extensions + metadata form.
- Dialects never know one another. No dialect imports, names, branches on or converts
  directly to another dialect; a conversion is the source dialect reading into the
  neutral form and the target dialect writing from it.

The cutover of the existing registry surface is planned separately; until it lands,
the sections above that describe the registry are historical.

## Amendment 2026-10-25: capability composition

Operator ruling of 2026-10-25 (CA/DI, "Corrigir todos").

- A server composes its Schema, ACL and Entry capabilities once, at construction. Each
  capability receives its owning server through the typed `parent_server` port
  (`t.Port[p.Ldif.ServerServer]`).
- The Entry capability receives its dialect's ACL capability through the required
  `acl_server` port (`t.Port[p.Ldif.AclServer]`). A composition that does not provide
  it fails when the capability is built, not during parsing.
- Entry parsing merges parsed ACL extensions through that injected capability. No
  capability looks up a parent at runtime, and none is constructed without its server;
  tests reach capabilities through the server's public `schema_server`, `acl_server`
  and `entry_server`.
