# FLEXT-LDIF Architecture

**Version**: 0.9.0 | **Updated**: 2025-02-17

This document describes the architecture in `src/flext_ldif`. It connects the
public facade to the underlying service layer, quirk discovery, and typed models
to show how the library processes LDIF while adapting to different LDAP servers.

## Architectural Goals

- Keep a single, stable facade for callers while allowing the implementation to
  evolve behind it.
- Separate RFC-compliant behaviour from server-specific differences via
  discoverable quirks.
- Provide predictable, typed inputs/outputs using Pydantic v2 models and
  flext-core `FlextResult`.
- Keep services small and focused so changes remain localized.

## Package Layout

```
src/flext_ldif/
├── api.py                # Public facade that wires and exposes services
├── base.py               # Shared service base with LDIF-specific config helper
├── config.py             # Configuration namespace for LDIF options
├── constants.py          # Enumerations and literal helpers
├── models.py             # Public aggregation of domain, processing, and result models
├── protocols.py          # Protocol contracts for services and quirks
├── services/             # Services for parsing, writing, conversion, filtering, etc.
├── servers/              # Server-specific quirks (Schema, Acl, Entry) auto-discovered at runtime
├── typings.py            # Typed helper aliases for service responses
└── utilities.py          # Cross-cutting helpers for DN, ACL, detection, validation
```

Supporting modules live under `_models/` (domain/config/processing/results) and
`_utilities/` (helpers split by concern). Type hints ship with `py.typed`.

## Core Components

### Facade (`api.py`)

`FlextLdif` is the single public entry point. It registers factories for filter
and categorization services, maps service types to concrete classes via
`SERVICE_MAPPING`, and lazily instantiates services on first access. The facade
inherits flext-core `FlextService`, exposing configuration (`FlextLdifConfig`),
logging, and `FlextResult` helpers to callers. Builder-style helpers (parse →
filter → write) reuse the same instance-level services to avoid redundant
initialization.

### Service Base (`base.py`)

All services inherit `FlextLdifServiceBase`, a thin wrapper around flext-core
`FlextService` that exposes namespaced configuration through the `ldif_config`
property.

### Services (`services/`)

Each service owns one responsibility:

- **Parsing (`services/parser.py`):** converts LDIF strings, files, or ldap3
  tuples into `ParseResponse` objects using entry quirks from the quirk
  registry.
- **Writing (`services/writer.py`):** serializes entries back to LDIF text with
  configurable encoding and wrapping.
- **Conversion (`services/conversion.py`):** translates entries between server
  types using source/target quirks.
- **Filtering & Categorization (`services/filters.py`, `services/categorization.py`):**
  apply typed filter criteria and grouping rules; factories are pre-registered to
  resolve circular dependencies.
- **Validation & Syntax (`services/validation.py`, `services/syntax.py`):**
  validate entries, schemas, and attribute syntax, delegating server nuances to
  quirks.
- **Analysis, Sorting, and Statistics (`services/analysis.py`, `services/sorting.py`,
  `services/statistics.py`):** provide helper routines for inspecting, ordering,
  and summarizing parsed datasets.
- **Detection, Entry Manipulation, DN helpers, and Migration (`services/detector.py`,
  `services/entries.py`, `services/dn.py`, `services/migration.py`):**
  identify server types, adjust entries, normalize DNs, and orchestrate migration
  flows.

All services return `FlextResult[T]` and share logging/configuration through the
base class. The writer and conversion services receive the quirk registry so
they can format entries for the target server type.

### Quirks (`services/server.py` and `servers/`)

`FlextLdifServer` discovers quirk implementations in `flext_ldif.servers` using
reflection. For each subclass of `FlextLdifServersBase`, it instantiates the
class, validates that nested `Schema`, `Acl`, and `Entry` components exist, and
registers them by `server_type`. Accessors (`schema`, `acl`, `entry`) return the
appropriate quirk instance for a normalized server type supplied by
`FlextLdifConstants`.

Concrete quirks include RFC, Oracle (OID/OUD), OpenLDAP variants, Active
Directory, 389 DS, Apache DS, Novell, Tivoli, and a relaxed fallback. Each quirk
encapsulates server-specific parsing, ACL handling, and schema interpretation
while keeping the facade and services unchanged.

### Models and Typing

Domain, processing, and result models live in `_models/` and are aggregated in
`models.py` under the `FlextLdifModels` namespace. They use Pydantic v2 for
validation and serialization. `typings.py` defines helper aliases for common
result shapes, and `constants.py` centralizes literals such as server types and
encodings.

## Control Flow Examples

### Parsing LDIF Text

1. Caller invokes `FlextLdif.parse` or `FlextLdifParser.parse`.
2. The parser resolves the effective server type (default `rfc`) and requests the
   entry quirk from `FlextLdifServer`.
3. The quirk parses the content and returns entries; the parser wraps them in
   `ParseResponse` with statistics and server metadata.

### Writing LDIF Text

1. Caller invokes `FlextLdif.write` with entries and optional format overrides.
2. Writer options are merged through `u.Configuration.build_options_from_kwargs`
   to combine defaults and explicit values.
3. The writer uses the shared quirk registry to format entries for the chosen
   server type before emitting LDIF text or writing to disk.

### Migration and Conversion

- Conversion services request both source and target quirks to normalize entries
  between server types.
- Migration pipelines compose parser, filters, conversion, and writer services to
  move datasets while preserving server-specific expectations.

## Extensibility and Quality Considerations

- **Adding a server:** create `servers/<name>.py` that subclasses
  `FlextLdifServersBase`, implement nested `Schema`, `Acl`, and `Entry`, and
  expose `server_type` and `priority`. `FlextLdifServer` will auto-register it on
  the next discovery cycle.
- **Adding a service:** subclass `FlextLdifServiceBase`, register a factory in
  `FlextLdifServiceRegistry`, and expose it through the facade mapping.
- **Reliability:** quirk discovery is idempotent and cached; typed models and
  `FlextResult` help prevent unexpected exceptions crossing boundaries.

The architecture favors discoverability and small, composable services so that
new behaviours can be added without widening the public API beyond the
`FlextLdif` facade.

## Related Documentation

**Within Project**:

- [Getting Started](getting-started.md) - Installation and basic usage
- [API Reference](api-reference.md) - Complete API documentation
- [Configuration](configuration.md) - Settings and environment management
- [Development](development.md) - Contributing and workflows
- [Integration Guide](guides/integration.md) - FLEXT ecosystem integration

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/architecture/overview.md) - Clean architecture and CQRS patterns
- [flext-ldap Architecture](https://github.com/organization/flext/tree/main/flext-ldap/docs/architecture/README.md) - Universal LDAP interface architecture

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
