# AGENTS.md — flext-ldif

> **Parent workspace law** lives in [`../AGENTS.md`](../AGENTS.md) — read it first.
> Universal engineering core: `~/.agents/UNIVERSAL_CORE.md`. Composition: global skills + parent/root `AGENTS.md` + this scope delta. Do not re-embed universal law.
>
> **Standalone / independent mode:** when `../AGENTS.md` does not resolve, pin the parent raw `AGENTS.md` URL to the same branch/release as this package (never `main`).

<!-- AIHUB-AGENTS-SCOPE-LOCAL-BEGIN -->
**Package:** `flext_ldif` · ~32.7k src LOC · deps: `flext-cli`, `flext-core`

## Overview

Enterprise LDIF processing — parse/write LDIF across many directory-server dialects. Base library for `flext-ldap`, `flext-tap-ldif`, `flext-target-ldif`, `flext-dbt-ldif`.

## Structure

```text
src/flext_ldif/
├── api.py                # FlextLdif facade: .categorization / .acl / .entry + registry resolution, migration, validation
├── base.py shared.py
├── servers/              # per-dialect handlers: rfc, relaxed, tivoli, novell, oud, oid, openldap(1), apache, ds389, ad …
│   └── __init__.py       # REGISTRY — if emptied, ALL parsing breaks fleet-wide
├── services/             # parser, writer, validation, conversion, acl, migration, pipeline, analysis
├── constants.py typings.py protocols.py models.py utilities.py   # AUTO-GENERATED facets
└── _constants/ _typings/ _protocols/ _models/ _utilities/
```

## Code Map

| Symbol | Kind | Location | Role |
|--------|------|----------|------|
| `FlextLdif` | class | `api.py` | facade: categorization / acl / entry / registry / migration / validation |
| server handlers | classes | `servers/*.py` | dialect-specific parse/write |
| services | classes | `services/*.py` | parser / writer / validation / conversion / acl / migration / pipeline |

## Conventions (specific to this package)

- **Server behavior is registry-selected via `server_type`** — never hardcode a dialect handler; go through the registry.
- Entries and results are typed `m.*` models returned directly (no dict roundtrip).

## Anti-Patterns / Gotchas

- **The `servers/__init__.py` registry is fleet-critical:** if its imports are emptied (a known past codegen regression), every downstream `parse_ldif` fails with `rfc`. Keep all server imports wired.
- Stray `test_typing_*.py.bak` files exist — not active code, don't treat as entrypoints.

## Commands

```bash
make check PROJECT=flext-ldif
make test  PROJECT=flext-ldif       # tests/{unit,integration,fixtures}
```
<!-- AIHUB-AGENTS-SCOPE-LOCAL-END -->
