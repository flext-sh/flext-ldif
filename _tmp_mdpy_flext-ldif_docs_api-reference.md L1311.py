# from flext-ldif/docs/api-reference.md:1311
# Works with ANY LDAP server using pure RFC baseline
server_type = None  # Pure RFC 2849/4512 compliance
server_type = "my_custom_ldap_v5"  # Unknown server = RFC baseline```
______________________________________________________________________

This API reference provides complete coverage of FLEXT-LDIF functionality, including the library-only interface, RFC-first architecture with MANDATORY server_registry, generic migration pipeline, and comprehensive servers system, while demonstrating integration with FLEXT ecosystem patterns and professional Python development practices.

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Examples - Practical usage patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldap Operations](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-ldap/docs/api-reference.md) - LDAP operations API
- [flext-meltano Pipelines](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-meltano/AGENTS.md) - Data integration and ELT orchestration

**External Resources**:

- [RFC 2849 - The LDAP Data Interchange Format (LDIF)](https://www.rfc-editor.org/rfc/rfc2849.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)
