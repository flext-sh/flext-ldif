# from flext-ldif_docs/refactoring/phase-2-service-layer.md:247
from __future__ import annotations


class FlextLdifServiceComposer:
    """Composes services for a given server type."""

    @classmethod
    def create_services(cls, settings: ServerConfig) -> Services:
        """Create and configure services for server."""
        return Services(
            schema=FlextLdifSchemaService(settings),
            acl=FlextLdifAclService(settings),
            entry=FlextLdifEntryService(settings),
        )


# Usage in servers
services = FlextLdifServiceComposer.create_services(self.settings)
attribute = services.schema.parse_attribute(attr_def)```
______________________________________________________________________

## Migration Path

### Step 1: Create ServiceConfig abstraction

- Extract Constants from servers
- Create settings classes for each server type
- Keep backward compatibility with Constants

### Step 2: Create services with new functionality

- FlextLdiifSchema
- FlextLdifAcl
- EntryTransformationService

### Step 3: Integrate services gradually

- Update RFC base server first
- Test thoroughly
- Roll out to other servers

### Step 4: Deprecate nested classes

- Move nested class logic to services
- Update all server implementations
- Remove nested classes

______________________________________________________________________

## Success Criteria

- [ ] All nested Schema, Acl, Entry classes moved to services
- [ ] Servers use ServiceComposer to get services
- [ ] Zero duplication of parsing/writing logic
- [ ] All tests pass with new architecture
- [ ] Services are independently testable
- [ ] Server-specific logic is in settings, not code
- [ ] Documentation updated with new patterns

______________________________________________________________________

## Related Documentation

- Hook system patterns (_Documentation coming soon_)
- [RFC 2849](https://tools.ietf.org/html/rfc2849) - LDIF Format Specification
- [RFC 4512](https://tools.ietf.org/html/rfc4512) - LDAP Schema Specification
