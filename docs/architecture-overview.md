# FLEXT-LDIF Architecture Overview

**Version**: 0.9.0 | **Updated**: 2025-02-17

This overview matches the implementation in `src/flext_ldif`. It highlights the
single public surface (`FlextLdif`), the focused service layer, and the quirk
registry that adapts behaviour per LDAP server.

## Executive Summary

FLEXT-LDIF is an LDIF processing library that exposes one facade (`FlextLdif`)
backed by a concise set of services (parse, write, analyze, filter, validate,
convert) and a quirk registry. RFC-compliant behaviour stays in the core while
server-specific adaptations are provided by discoverable quirks.

## System Context

- **Consumers:** application code imports `FlextLdif` to parse or write LDIF,
  convert between server types, or categorize entries.
- **Dependencies:** relies on flext-core for configuration, logging, and the
  `FlextResult` monadic API; uses Pydantic v2 for typed models.
- **External interfaces:** reads/writes LDIF files or strings and adapts to
  server-specific formats through quirks.

## Container & Component View

- **Facade (`api.py`):** `FlextLdif` is the single entry point. It wires
  services through `FlextLdifServiceRegistry`, lazily initializes them on first
  access via `SERVICE_MAPPING`, and exposes flext-core configuration helpers.
- **Services (`services/`):** each module owns a single responsibility—parsing,
  writing, conversion, filtering, validation, syntax handling, entry
  manipulation, analysis, sorting, and statistics. All services inherit
  `FlextLdifServiceBase` for consistent logging and config access.
- **Quirk registry (`services/server.py`):** discovers server implementations
  under `servers/`, validates protocol compliance, and returns the appropriate
  `Schema`, `Acl`, or `Entry` quirk for a requested server type.
- **Server quirks (`servers/`):** concrete behaviours for RFC, Oracle (OID/OUD),
  OpenLDAP variants, Active Directory, 389 DS, Apache DS, Novell, Tivoli, and a
  relaxed parser. Each quirk exposes nested `Schema`, `Acl`, and `Entry`
  implementations.
- **Models and configuration (`models.py`, `_models/`, `config.py`):** typed
  domain objects, processing responses, metadata, and LDIF-specific
  configuration wrapped in a single public namespace.

## Code-Level Architecture

1. `FlextLdif` registers factories for filters and categorization, then lazily
   instantiates services on demand through `FlextLdif.SERVICE_MAPPING` (parser,
   writer, entries, processing, detector, filters, categorization, conversion,
   validation, syntax, ACL, analysis).
2. Services inherit from `FlextLdifServiceBase`, gaining namespaced
   `ldif_config` access and `FlextResult` helpers.
3. When a service needs server-specific behaviour (for example, parsing or
   validation), it fetches quirks via `FlextLdifServer` using the normalized
   server type from `FlextLdifConstants`.
4. Results and metadata are expressed through `FlextLdifModels` types, ensuring
   consistent inputs/outputs across the library.

## Data and Error Handling

- Models rely on Pydantic v2 for validation, surfacing data issues early.
- All operations return `FlextResult[T]`, encouraging explicit handling of
  failure paths instead of exceptions leaking across boundaries.

## Quality Attributes

- **Maintainability:** modular services and strict protocol contracts for quirks
  limit cross-cutting changes.
- **Extensibility:** new server types require only a new module under
  `servers/` that inherits `FlextLdifServersBase` and exposes `server_type` and
  `priority`.
- **Reliability:** idempotent quirk discovery and typed responses reduce hidden
  state and make integration predictable.

## Evolution

Planned changes should continue to preserve the single-facade approach, keep
quirks discoverable, and extend services via the registry rather than adding
parallel APIs. Any new behaviour should be added as a focused service that
composes existing models and quirks.
