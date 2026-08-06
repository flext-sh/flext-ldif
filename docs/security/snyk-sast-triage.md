# Triagem Snyk Code (SAST) — flext-sh/flext-ldif

Gerado a partir do scan Snyk da org Datacosmos (dump 2026-08-06).

Bead de rastreio: `mro-l65n`

## Resumo

**1 achados** — critical 0, high 0, medium 1, low 0

| categoria | achados |
|---|---|
| Use of Hardcoded Passwords | 1 |

## Achados

Ordenados por severidade. Coluna **Decisão** a preencher: `corrigir` / `falso-positivo` / `risco-aceito`.

| # | sev | categoria | arquivo | linha | CWE | Decisão |
|---|---|---|---|---|---|---|
| 1 | medium | Use of Hardcoded Passwords | `src/flext_ldif/constants.py` | 458 | CWE-259,CWE-798 | |

## Como triar

1. Abrir `arquivo:linha` e seguir o fluxo de dados até o sink.
2. Classificar:
   - **corrigir** — entrada realmente controlável por terceiro chega ao sink sem sanitização.
   - **falso-positivo** — ex.: credencial em fixture de teste, path derivado de constante interna, entrada já validada a montante. Registrar em `.snyk` com justificativa.
   - **risco-aceito** — exposição real porém tolerável no contexto; registrar com prazo de revisão.
3. Preencher a coluna Decisão nesta tabela e abrir tarefas de correção para os itens `corrigir`.

## Notas

- `Use of Hardcoded Passwords` / `Credentials` em código de teste e fixtures costuma ser falso positivo — verificar antes de alterar.
- `Path Traversal` só é explorável se o caminho vier de entrada externa; paths montados de constantes não são.
- Dados brutos com `issue_id` e `key` do Snyk: `~/snyk-violations/sast/flext-sh__flext-ldif.sast.json`

