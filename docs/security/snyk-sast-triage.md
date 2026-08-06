# Triagem Snyk Code (SAST) — flext-sh/flext-ldif

Gerado do scan Snyk (dump 2026-08-06). Bead: `mro-l65n`

## Resumo

**1 achados** — critical 0, high 0, medium 1, low 0

| categoria | achados |
|---|---|
| Use of Hardcoded Passwords | 1 |

## Como usar este documento

Cada achado traz o **código real** extraído da worktree (linha `>>>` = sink reportado), a regra completa e o CWE.
Preencha **Decisão**: `corrigir` / `falso-positivo` (registrar em `.snyk`) / `risco-aceito` (com prazo).

## Achados

### 1 · 🟡 MEDIUM · Use of Hardcoded Passwords
**Local**: `src/flext_ldif/constants.py:458` · **CWE**: -

```python
      454              "substring_assertion": "string",
      455              "teletex_terminal_identifier": "string",
      456              "telex_number": "string",
      457              "unique_member": "dn",
>>>   458              "user_password": "binary",
      459              "user_certificate": "binary",
      460              "ca_certificate": "binary",
      461              "authority_revocation_list": "binary",
      462              "certificate_revocation_list": "binary",
```

**Decisão**: 

