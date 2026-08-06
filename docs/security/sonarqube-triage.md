# Triagem SonarCloud — flext-sh/flext-ldif

Gerado do dump da plataforma SonarCloud (2026-08-06).

Bead de rastreio: `mro-2wjm.10`

## Resumo

**91 issues** — BLOCKER 0, CRITICAL 42, MAJOR 32, MINOR 17
Tipos: VULNERABILITY 5, BUG 5, CODE_SMELL 81

| regra | issues |
|---|---|
| `python:S3776` | 38 |
| `python:S108` | 7 |
| `python:S6353` | 6 |
| `python:S8786` | 5 |
| `python:S3358` | 4 |
| `python:S7504` | 4 |
| `python:S1192` | 3 |
| `python:S5869` | 3 |

## Issues

Coluna **Decisão**: `corrigir` / `falso-positivo` / `risco-aceito`.

| # | sev | tipo | regra | componente | linha | Decisão |
|---|---|---|---|---|---|---|
| 1 | CRITICAL | CODE_SMELL | `python:S3776` | `examples/05_schema_operations.py` | 91 | |
| 2 | CRITICAL | CODE_SMELL | `python:S3776` | `examples/05_schema_operations.py` | 179 | |
| 3 | CRITICAL | CODE_SMELL | `python:S3776` | `examples/05_schema_operations.py` | 248 | |
| 4 | CRITICAL | CODE_SMELL | `python:S1192` | `src/flext_ldif/_utilities/dn.py` | 120 | |
| 5 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/dn.py` | 298 | |
| 6 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/dn.py` | 550 | |
| 7 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/dn.py` | 779 | |
| 8 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/dn.py` | 889 | |
| 9 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/entry.py` | 243 | |
| 10 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/entry.py` | 556 | |
| 11 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/entry.py` | 633 | |
| 12 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/entry.py` | 697 | |
| 13 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/metadata.py` | 343 | |
| 14 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/parser.py` | 134 | |
| 15 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/parser.py` | 285 | |
| 16 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/pipeline.py` | 94 | |
| 17 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/server.py` | 101 | |
| 18 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/_utilities/writer.py` | 65 | |
| 19 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_base/entry.py` | 252 | |
| 20 | CRITICAL | CODE_SMELL | `python:S1192` | `src/flext_ldif/servers/_base/schema.py` | 546 | |
| 21 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/acl.py` | 301 | |
| 22 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/acl.py` | 496 | |
| 23 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/acl_assemble.py` | 38 | |
| 24 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/acl_convert_oud.py` | 78 | |
| 25 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/entry.py` | 259 | |
| 26 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/entry.py` | 523 | |
| 27 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oid/schema.py` | 436 | |
| 28 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/aci.py` | 36 | |
| 29 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/aci.py` | 104 | |
| 30 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/acl.py` | 130 | |
| 31 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/acl.py` | 244 | |
| 32 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/acl.py` | 279 | |
| 33 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/acl_metadata.py` | 156 | |
| 34 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/comments.py` | 123 | |
| 35 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/comments.py` | 194 | |
| 36 | CRITICAL | CODE_SMELL | `python:S1192` | `src/flext_ldif/servers/_oud/constants.py` | 216 | |
| 37 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/entry.py` | 154 | |
| 38 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_oud/schema.py` | 250 | |
| 39 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/_rfc/schema.py` | 18 | |
| 40 | CRITICAL | CODE_SMELL | `python:S5797` | `src/flext_ldif/servers/openldap1.py` | 216 | |
| 41 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/servers/relaxed.py` | 557 | |
| 42 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldif/services/conversion_schema.py` | 31 | |
| 43 | MAJOR | VULNERABILITY | `githubactions:S8264` | `.github/workflows/docs.yml` | 18 | |
| 44 | MAJOR | VULNERABILITY | `githubactions:S8233` | `.github/workflows/docs.yml` | 19 | |
| 45 | MAJOR | VULNERABILITY | `githubactions:S8233` | `.github/workflows/docs.yml` | 20 | |
| 46 | MAJOR | CODE_SMELL | `python:S3358` | `examples/05_schema_operations.py` | 223 | |
| 47 | MAJOR | VULNERABILITY | `text:S8565` | `pyproject.toml` | - | |
| 48 | MAJOR | CODE_SMELL | `python:S8786` | `src/flext_ldif/_constants/base.py` | 124 | |
| 49 | MAJOR | CODE_SMELL | `python:S8786` | `src/flext_ldif/_constants/base.py` | 125 | |
| 50 | MAJOR | CODE_SMELL | `python:S5869` | `src/flext_ldif/_constants/base.py` | 141 | |
| 51 | MAJOR | CODE_SMELL | `python:S5869` | `src/flext_ldif/_constants/base.py` | 141 | |
| 52 | MAJOR | CODE_SMELL | `python:S8786` | `src/flext_ldif/_constants/base.py` | 210 | |
| 53 | MAJOR | BUG | `python:S5855` | `src/flext_ldif/_constants/base.py` | 217 | |
| 54 | MAJOR | BUG | `python:S5855` | `src/flext_ldif/_constants/base.py` | 220 | |
| 55 | MAJOR | CODE_SMELL | `python:S107` | `src/flext_ldif/_models/domain_entry.py` | 884 | |
| 56 | MAJOR | CODE_SMELL | `python:S107` | `src/flext_ldif/_models/domain_entry.py` | 944 | |
| 57 | MAJOR | BUG | `pythonbugs:S2583` | `src/flext_ldif/_utilities/acl.py` | 521 | |
| 58 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/_utilities/collection_ldif.py` | 60 | |
| 59 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/_utilities/entry.py` | 672 | |
| 60 | MAJOR | CODE_SMELL | `python:S3358` | `src/flext_ldif/api.py` | 84 | |
| 61 | MAJOR | VULNERABILITY | `python:S2068` | `src/flext_ldif/constants.py` | 458 | |
| 62 | MAJOR | CODE_SMELL | `python:S3358` | `src/flext_ldif/servers/_oud/acl.py` | 291 | |
| 63 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/servers/_oud/acl.py` | 310 | |
| 64 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/servers/_rfc/schema.py` | 593 | |
| 65 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/servers/_rfc/schema.py` | 605 | |
| 66 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/servers/_rfc/schema.py` | 661 | |
| 67 | MAJOR | BUG | `pythonbugs:S2583` | `src/flext_ldif/servers/ad.py` | 325 | |
| 68 | MAJOR | CODE_SMELL | `python:S5869` | `src/flext_ldif/servers/openldap.py` | 111 | |
| 69 | MAJOR | CODE_SMELL | `python:S8786` | `src/flext_ldif/servers/openldap.py` | 122 | |
| 70 | MAJOR | CODE_SMELL | `python:S8786` | `src/flext_ldif/servers/openldap1.py` | 98 | |
| 71 | MAJOR | CODE_SMELL | `python:S108` | `src/flext_ldif/services/acl.py` | 67 | |
| 72 | MAJOR | CODE_SMELL | `python:S3358` | `src/flext_ldif/services/categorization.py` | 213 | |
| 73 | MAJOR | CODE_SMELL | `python:S1854` | `src/flext_ldif/services/conversion_acl_preserve.py` | 98 | |
| 74 | MAJOR | BUG | `pythonbugs:S2583` | `src/flext_ldif/services/filters.py` | 46 | |
| 75 | MINOR | CODE_SMELL | `python:S7504` | `conftest.py` | 20 | |
| 76 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/_constants/base.py` | 204 | |
| 77 | MINOR | CODE_SMELL | `python:S116` | `src/flext_ldif/_utilities/transformers.py` | 20 | |
| 78 | MINOR | CODE_SMELL | `python:S116` | `src/flext_ldif/_utilities/transformers.py` | 23 | |
| 79 | MINOR | CODE_SMELL | `python:S5713` | `src/flext_ldif/servers/_base/schema.py` | 305 | |
| 80 | MINOR | CODE_SMELL | `python:S5713` | `src/flext_ldif/servers/_base/schema.py` | 319 | |
| 81 | MINOR | CODE_SMELL | `python:S7504` | `src/flext_ldif/servers/_oid/entry.py` | 539 | |
| 82 | MINOR | CODE_SMELL | `python:S7504` | `src/flext_ldif/servers/_oid/entry.py` | 677 | |
| 83 | MINOR | CODE_SMELL | `python:S7508` | `src/flext_ldif/servers/ad.py` | 359 | |
| 84 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/servers/relaxed.py` | 32 | |
| 85 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/servers/relaxed.py` | 32 | |
| 86 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/servers/relaxed.py` | 36 | |
| 87 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/servers/relaxed.py` | 36 | |
| 88 | MINOR | CODE_SMELL | `python:S6353` | `src/flext_ldif/servers/relaxed.py` | 36 | |
| 89 | MINOR | CODE_SMELL | `python:S5685` | `src/flext_ldif/services/acl.py` | 78 | |
| 90 | MINOR | CODE_SMELL | `python:S7504` | `src/flext_ldif/services/filters.py` | 178 | |
| 91 | MINOR | CODE_SMELL | `python:S8714` | `tests/integration/fixtures.py` | 119 | |

## Como triar

1. **BLOCKER e CRITICAL primeiro**, e todo VULNERABILITY independente de severidade.
2. Classificar: **corrigir**, **falso-positivo** (marcar na plataforma SonarCloud com justificativa), **risco-aceito** (com prazo).
3. CODE_SMELL em volume alto sugere padrão — corrigir a causa raiz, não issue a issue.

Dados brutos: `~/sonarqube-violations/by-repo/flext-sh__flext-ldif.json`

