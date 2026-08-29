# Triagem SonarCloud — flext-sh/flext-ldif

Gerado do dump da plataforma SonarCloud (2026-08-06).

Bead: `mro-2wjm.10`

## Resumo

**91 issues** — BLOCKER 0, CRITICAL 42, MAJOR 32, MINOR 17
Tipos: VULNERABILITY 5, BUG 5, CODE_SMELL 81 · **Debt total: 1046min**

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
| `pythonbugs:S2583` | 3 |
| `githubactions:S8233` | 2 |

## Como usar

Cada issue traz a **mensagem do SonarQube** (descreve o problema e o impacto), o **código real** (linha `>>>`), o tipo e o effort estimado.
**Decisão**: `corrigir` / `falso-positivo` (marcar na plataforma com justificativa) / `risco-aceito`. Ordem: BLOCKER → CRITICAL → VULNERABILITY → MAJOR. CODE_SMELL em volume pede correção de padrão.

## Issues

### 1 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `examples/05_schema_operations.py:91` · **Effort**: 7min

> Refactor this function to reduce its Cognitive Complexity from 17 to the 15 allowed.

```python
       87              schema_entries.append(entry)
       88      return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)
       89  
       90  
>>>    91  def parallel_schema_validation() -> p.Result[t.JsonMapping]:
       92      """Validate schema with comprehensive error analysis."""
       93      api = ldif()
       94      test_entries: list[m.Ldif.Entry] = []
       95      for i in range(30):
```

**Decisão**: pendente

### 2 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `examples/05_schema_operations.py:179` · **Effort**: 17min

> Refactor this function to reduce its Cognitive Complexity from 27 to the 15 allowed.

```python
      175      analysis["error_analysis"] = error_analysis
      176      return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(analysis))
      177  
      178  
>>>   179  def schema_migration_pipeline() -> p.Result[t.JsonMapping]:
      180      """Schema-aware migration pipeline with validation."""
      181      api = ldif()
      182      migration_dir = Path("examples/schema_migration")
      183      source_dir = migration_dir / "source"
```

**Decisão**: pendente

### 3 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `examples/05_schema_operations.py:248` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      244          t.json_mapping_adapter().validate_python(migration_results)
      245      )
      246  
      247  
>>>   248  def batch_schema_operations() -> p.Result[t.JsonMapping]:
      249      """Batch schema operations with validation."""
      250      api = ldif()
      251      schema_batches: list[tuple[str, list[m.Ldif.Entry]]] = []
      252      core_attrs: list[m.Ldif.Entry] = []
```

**Decisão**: pendente

### 4 · 🟠 CRITICAL · CODE_SMELL · `python:S1192`
**Local**: `src/flext_ldif/_utilities/dn.py:120` · **Effort**: 6min

> Define a constant instead of duplicating this literal "[\\t\\r\\n\\x0b\\x0c]" 3 times.

```python
      116          }
      117          result = original_dn
      118          transform_rules: t.MutableSequenceOf[tuple[str, str, str, str, str]] = [
      119              (
>>>   120                  "[\\t\\r\\n\\x0b\\x0c]",
      121                  "[\\t\\r\\n\\x0b\\x0c]",
      122                  " ",
      123                  c.Ldif.TransformationType.TAB_NORMALIZED,
      124                  "had_tab_chars",
```

**Decisão**: pendente

### 5 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/dn.py:298` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      294          ]
      295          return all(check() for check in checks)
      296  
      297      @staticmethod
>>>   298      def _validate_escape_sequences(dn_str: str) -> bool:
      299          r"""Validate escape sequences in DN string.
      300  
      301          RFC 4514 Section 2.4: Implementations MUST allow UTF-8 characters
      302          to appear in values (both in their UTF-8 form and in their escaped form).
```

**Decisão**: pendente

### 6 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/dn.py:550` · **Effort**: 10min

> Refactor this function to reduce its Cognitive Complexity from 20 to the 15 allowed.

```python
      546          base_dn_lower = base_dn_str.lower().strip()
      547          return dn_lower == base_dn_lower or dn_lower.endswith(f",{base_dn_lower}")
      548  
      549      @staticmethod
>>>   550      def is_valid_dn_string(
      551          value: str, *, strict: bool = True
      552      ) -> tuple[bool, t.MutableSequenceOf[str]]:
      553          """Validate DN attribute value per RFC 4514 string production."""
      554          errors: t.MutableSequenceOf[str] = []
```

**Decisão**: pendente

### 7 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/dn.py:779` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      775      @staticmethod
      776      def split(dn: m.Ldif.DN) -> t.MutableSequenceOf[str]: ...
      777  
      778      @staticmethod
>>>   779      def split(dn: str | m.Ldif.DN) -> t.MutableSequenceOf[str]:
      780          r"""Split DN string into individual RDN components per RFC 4514.
      781  
      782          RFC 4514 Section 2 ABNF:
      783          ========================
```

**Decisão**: pendente

### 8 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/dn.py:889` · **Effort**: 19min

> Refactor this function to reduce its Cognitive Complexity from 29 to the 15 allowed.

```python
      885                  i += 1
      886          return "".join(result)
      887  
      888      @staticmethod
>>>   889      def transform_entry_base_dn(
      890          entry: m.Ldif.Entry,
      891          source_dn: str,
      892          target_dn: str,
      893          dn_valued_attributes: frozenset[str] | None = None,
```

**Decisão**: pendente

### 9 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/entry.py:243` · **Effort**: 12min

> Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.

```python
      239              )
      240          return violations
      241  
      242      @staticmethod
>>>   243      def validate_attribute_descriptions(
      244          entry: p.Ldif.EntryValidationSubject,
      245      ) -> t.MutableSequenceOf[str]:
      246          """Validate attribute descriptions per RFC 4512 section 2.5.
      247  
```

**Decisão**: pendente

### 10 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/entry.py:556` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      552          differences[mk.HAS_DIFFERENCES] = True
      553          return differences
      554  
      555      @staticmethod
>>>   556      def analyze_differences(
      557          entry_attrs: t.Ldif.MetadataInputMapping,
      558          converted_attrs: MutableMapping[
      559              str, t.MutableSequenceOf[t.Ldif.AttributeValue]
      560          ],
```

**Decisão**: pendente

### 11 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/entry.py:633` · **Effort**: 12min

> Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.

```python
      629              original_attribute_case,
      630          )
      631  
      632      @staticmethod
>>>   633      def convert_boolean_attributes(
      634          attributes: t.MappingKV[
      635              str, t.MutableSequenceOf[str] | t.MutableSequenceOf[bytes] | str | bytes
      636          ],
      637          boolean_attr_names: set[str],
```

**Decisão**: pendente

### 12 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/entry.py:697` · **Effort**: 6min

> Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.

```python
      693              return has_schema_dn
      694          return has_schema_dn or has_schema_objectclass or has_schema_attrs
      695  
      696      @staticmethod
>>>   697      def matches_criteria(
      698          entry: p.Ldif.Entry,
      699          settings: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
      700          **kwargs: str | float | bool | None,
      701      ) -> bool:
```

**Decisão**: pendente

### 13 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/metadata.py:343` · **Effort**: 13min

> Refactor this function to reduce its Cognitive Complexity from 23 to the 15 allowed.

```python
      339              details["oid_spacing_after"] = oid_match.group(2)
      340          return details
      341  
      342      @staticmethod
>>>   343      def _extract_prefix_details(definition: str) -> t.MutableStrMapping:
      344          """Extract attribute/ObjectClass prefix details."""
      345          details: t.MutableStrMapping = {}
      346          if "attributetypes:" in definition.lower():
      347              attr_match = c.Ldif.LDIF_ATTR_TYPES_PREFIX_RE.search(definition)
```

**Decisão**: pendente

### 14 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/parser.py:134` · **Effort**: 35min

> Refactor this function to reduce its Cognitive Complexity from 45 to the 15 allowed.

```python
      130          if current_op is not None:
      131              change_operations.append(current_op)
      132  
      133      @staticmethod
>>>   134      def parse_ldif_record(lines: t.MutableSequenceOf[str]) -> p.Result[m.Ldif.Entry]:
      135          """Parse a single unfolded LDIF record into Entry."""
      136          dn = ""
      137          attrs: t.MutableStrSequenceMapping = {}
      138          attribute_metadata: MutableMapping[str, t.MutableAttributeMapping] = {}
```

**Decisão**: pendente

### 15 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/parser.py:285` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      281              records.append(current_record)
      282          return records
      283  
      284      @staticmethod
>>>   285      def ext(metadata: t.Ldif.MetadataInputMapping) -> t.MutableStrSequenceMapping:
      286          """Extract extension information from parsed metadata."""
      287  
      288          def _as_str_list(
      289              value: t.MutableSequenceOf[t.JsonValue] | t.JsonValue | None,
```

**Decisão**: pendente

### 16 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/pipeline.py:94` · **Effort**: 10min

> Refactor this function to reduce its Cognitive Complexity from 20 to the 15 allowed.

```python
       90              return r[
       91                  t.MutableSequenceOf[FlextLdifUtilitiesPipeline.ValidationResult]
       92              ].ok(results)
       93  
>>>    94          def validate_one(
       95              self, entry: m.Ldif.Entry
       96          ) -> p.Result[FlextLdifUtilitiesPipeline.ValidationResult]:
       97              """Validate a single entry."""
       98              errors: t.MutableSequenceOf[str] = []
```

**Decisão**: pendente

### 17 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/server.py:101` · **Effort**: 10min

> Refactor this function to reduce its Cognitive Complexity from 20 to the 15 allowed.

```python
       97              return c.Ldif.ServerTypes(server_type_lower)
       98          return None
       99  
      100      @staticmethod
>>>   101      def _get_type_from_nested_class(target_cls: type) -> c.Ldif.ServerTypes | None:
      102          """Extract server type from nested class via parent's Constants."""
      103          qualname_parts = target_cls.__qualname__.split(".")
      104          if len(qualname_parts) > 1:
      105              parent_module = sys.modules.get(target_cls.__module__)
```

**Decisão**: pendente

### 18 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/_utilities/writer.py:65` · **Effort**: 55min

> Refactor this function to reduce its Cognitive Complexity from 65 to the 15 allowed.

```python
       61              ldif_text += "\n"
       62          return ldif_text
       63  
       64      @staticmethod
>>>    65      def fold_line(
       66          line: str, width: int = c.Ldif.LINE_FOLD_WIDTH
       67      ) -> t.MutableSequenceOf[str]:
       68          """Fold long LDIF line according to RFC 2849 §3."""
       69          if not line:
```

**Decisão**: pendente

### 19 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_base/entry.py:252` · **Effort**: 1h56min

> Refactor this function to reduce its Cognitive Complexity from 126 to the 15 allowed.

```python
      248          return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
      249              "Must be implemented by subclass"
      250          )
      251  
>>>   252      def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
      253          """Write Entry model to RFC-compliant LDIF string (internal)."""
      254          output_lines: t.MutableSequenceOf[str] = []
      255          fold_long_lines = True
      256          line_width = c.Ldif.LINE_FOLD_WIDTH
```

**Decisão**: pendente

### 20 · 🟠 CRITICAL · CODE_SMELL · `python:S1192`
**Local**: `src/flext_ldif/servers/_base/schema.py:546` · **Effort**: 8min

> Define a constant instead of duplicating this literal "Must be implemented by subclass" 4 times.

```python
      542          self, attr_definition: str
      543      ) -> p.Result[m.Ldif.SchemaAttribute]:
      544          """Parse server-specific attribute definition (internal)."""
      545          del attr_definition
>>>   546          return r[m.Ldif.SchemaAttribute].fail("Must be implemented by subclass")
      547  
      548      def _parse_objectclass(
      549          self, oc_definition: str
      550      ) -> p.Result[m.Ldif.SchemaObjectClass]:
```

**Decisão**: pendente

### 21 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/acl.py:301` · **Effort**: 6min

> Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.

```python
      297          extensions = getattr(metadata, "extensions", None)
      298          # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: copy the plain mapping.
      299          return dict(extensions) if extensions is not None else {}
      300  
>>>   301      def _format_extensions(
      302          self, meta_extensions: t.Ldif.MutableMetadataMapping
      303      ) -> t.MutableSequenceOf[str]:
      304          """Format extension values based on metadata key type."""
      305          extensions: t.MutableSequenceOf[str] = []
```

**Decisão**: pendente

### 22 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/acl.py:496` · **Effort**: 10min

> Refactor this function to reduce its Cognitive Complexity from 20 to the 15 allowed.

```python
      492                  acl_line_length=len(acl_line),
      493              )
      494              return r[m.Ldif.Acl].fail_op("OID ACL parsing", e)
      495  
>>>   496      def _parse_oid_specific_acl_core(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
      497          """Parse OID-specific ACL data into the canonical ACL model."""
      498          target_dn, target_attrs = self._extract_oid_target(acl_line)
      499          if not target_dn:
      500              target_dn = "entry"
```

**Decisão**: pendente

### 23 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/acl_assemble.py:38` · **Effort**: 22min

> Refactor this function to reduce its Cognitive Complexity from 32 to the 15 allowed.

```python
       34          )
       35          return f"{container} {perm_type} by {subject_name}"
       36  
       37      @classmethod
>>>    38      def build_aci_rule(
       39          cls, rule: m.Ldif.OidAclRule, *, base_dn: str = ""
       40      ) -> p.Result[m.Ldif.AciRule]:
       41          """Assemble a parsed OID rule into one OUD :class:`m.Ldif.AciRule`.
       42  
```

**Decisão**: pendente

### 24 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/acl_convert_oud.py:78` · **Effort**: 12min

> Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.

```python
       74                  )
       75          return granted
       76  
       77      @classmethod
>>>    78      def convert_permissions(
       79          cls, permissions: t.StrSequence, *, is_entry: bool
       80      ) -> p.Result[t.StrSequence]:
       81          """Convert OID permission tokens to the ordered OUD allow set.
       82  
```

**Decisão**: pendente

### 25 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/entry.py:259` · **Effort**: 16min

> Refactor this function to reduce its Cognitive Complexity from 26 to the 15 allowed.

```python
      255              current_extensions[c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT] = (
      256                  constrain_to_added
      257              )
      258  
>>>   259      def _parse_metadata_boolean_flags(
      260          self, entry_data: m.Ldif.Entry
      261      ) -> MutableMapping[str, t.MutableAttributeMapping]:
      262          """Extract boolean conversions from entry metadata."""
      263          mk = c.Ldif
```

**Decisão**: pendente

### 26 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/entry.py:523` · **Effort**: 26min

> Refactor this function to reduce its Cognitive Complexity from 36 to the 15 allowed.

```python
      519              if mapped_key and (not current_extensions.get(mapped_key)):
      520                  current_extensions[mapped_key] = value
      521  
      522      @staticmethod
>>>   523      def _normalize_schema_values(attrs: t.MutableStrSequenceMapping) -> None:
      524          """Normalize OID matching rules and syntax OIDs in schema definition strings.
      525  
      526          Applies MATCHING_RULE_TO_RFC and SYNTAX_OID_TO_RFC conversions to the raw
      527          attributeTypes/objectClasses/matchingRules value strings. Handles context-aware
```

**Decisão**: pendente

### 27 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oid/schema.py:436` · **Effort**: 9min

> Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.

```python
      432              return transformed_attr
      433          return attr_data
      434  
      435      @override
>>>   436      def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
      437          """Write Oracle OID attribute definition (Phase 2: Denormalization)."""
      438          attr_copy = attr_data.model_copy(deep=True)
      439          source_rules: t.JsonPayload | None = None
      440          source_syntax: t.JsonPayload | None = None
```

**Decisão**: pendente

### 28 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/aci.py:36` · **Effort**: 38min

> Refactor this function to reduce its Cognitive Complexity from 48 to the 15 allowed.

```python
       32                  return value
       33          return None
       34  
       35      @staticmethod
>>>    36      def find_aci_values(
       37          entry: m.Ldif.Entry, original_attrs: t.AttributeMapping
       38      ) -> t.MutableSequenceOf[str] | str | None:
       39          """Find ACI values from entry attributes, original_attrs, or commented metadata."""
       40          normalize = FlextLdifServersOudAciMixin.normalize_aci_value_simple
```

**Decisão**: pendente

### 29 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/aci.py:104` · **Effort**: 8min

> Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.

```python
      100              return [u.to_str(item) for item in value]
      101          return u.to_str(value)
      102  
      103      @staticmethod
>>>   104      def process_aci_list_for_finalize(
      105          aci_values: t.MutableSequenceOf[str] | str,
      106          acl_server: p.Ldif.AclServer,
      107          current_extensions: t.Ldif.MutableMetadataInputMapping,
      108      ) -> None:
```

**Decisão**: pendente

### 30 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/acl.py:130` · **Effort**: 21min

> Refactor this function to reduce its Cognitive Complexity from 31 to the 15 allowed.

```python
      126      def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
      127          """Get RFC + OUD extensions."""
      128          return [*self.RFC_ACL_ATTRIBUTES, *self.OUD_ACL_ATTRIBUTES]
      129  
>>>   130      def _build_aci_permissions(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
      131          """Build ACI permissions clause from ACL model."""
      132          perms = acl_data.permissions
      133          target_perms_dict: t.MappingKV[str, t.JsonPayload] | None = None
      134          if not perms and acl_data.metadata:
```

**Decisão**: pendente

### 31 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/acl.py:244` · **Effort**: 17min

> Refactor this function to reduce its Cognitive Complexity from 27 to the 15 allowed.

```python
      240              subject_type, filtered_value, bind_operator
      241          )
      242          return formatted
      243  
>>>   244      def _build_aci_target(self, acl_data: m.Ldif.Acl) -> str:
      245          """Build ACI target clause from ACL model."""
      246          target = acl_data.target
      247          if not target and acl_data.metadata:
      248              extensions = acl_data.metadata.extensions
```

**Decisão**: pendente

### 32 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/acl.py:279` · **Effort**: 6min

> Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.

```python
      275              separator=" || ",
      276          )
      277          return clause
      278  
>>>   279      def _extract_and_resolve_acl_subject(
      280          self, acl_data: m.Ldif.Acl
      281      ) -> tuple[str | None, str, str]:
      282          """Extract metadata and resolve subject type and value in one pass."""
      283          ext = acl_data.metadata.extensions if acl_data.metadata else None
```

**Decisão**: pendente

### 33 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/acl_metadata.py:156` · **Effort**: 12min

> Refactor this function to reduce its Cognitive Complexity from 22 to the 15 allowed.

```python
      152          )
      153          return updated_entry
      154  
      155      @staticmethod
>>>   156      def process_parsed_acl_extensions(
      157          acl_extensions: t.Ldif.MetadataInputMapping,
      158          current_extensions: t.Ldif.MutableMetadataInputMapping,
      159      ) -> None:
      160          """Process parsed ACL extensions and add to current extensions."""
```

**Decisão**: pendente

### 34 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/comments.py:123` · **Effort**: 9min

> Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.

```python
      119              if rejection_reason_raw:
      120                  comment_lines.append(f"# [REJECTION] {rejection_reason_raw}")
      121  
      122      @staticmethod
>>>   123      def _add_transformation_comments(
      124          comment_lines: t.MutableSequenceOf[str],
      125          entry: m.Ldif.Entry,
      126          format_options: m.Ldif.WriteFormatOptions | None = None,
      127      ) -> None:
```

**Decisão**: pendente

### 35 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/comments.py:194` · **Effort**: 6min

> Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.

```python
      190          if comment_lines:
      191              comment_lines.append("")
      192  
      193      @staticmethod
>>>   194      def _collect_acl_from_extensions(
      195          entry: m.Ldif.Entry,
      196          acl_comments_dict: t.MutableStrSequenceMapping,
      197          acl_attr_names_to_skip: set[str],
      198      ) -> None:
```

**Decisão**: pendente

### 36 · 🟠 CRITICAL · CODE_SMELL · `python:S1192`
**Local**: `src/flext_ldif/servers/_oud/constants.py:216` · **Effort**: 8min

> Define a constant instead of duplicating this literal "cn=settings" 4 times.

```python
      212          "groups",
      213          "rejected",
      214      )
      215      DN_DETECTION_PATTERNS: ClassVar[tuple[t.StrSequence, ...]] = (
>>>   216          ("cn=settings", "cn=schema"),
      217          ("cn=settings", "cn=directory"),
      218          ("cn=settings", "cn=ds"),
      219      )
      220      KEYWORD_PATTERNS: ClassVar[t.StrSequence] = ("pwd", "password")
```

**Decisão**: pendente

### 37 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/entry.py:154` · **Effort**: 15min

> Refactor this function to reduce its Cognitive Complexity from 25 to the 15 allowed.

```python
      150              entry.metadata = entry.metadata.model_copy(update={"extensions": existing})
      151          return r[m.Ldif.Entry].ok(entry)
      152  
      153      @override
>>>   154      def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
      155          """Validate OUD ACI macros and merge ACL metadata into the parsed entry."""
      156          attrs_dict: t.MutableStrSequenceMapping = (
      157              entry.attributes.attributes if entry.attributes is not None else {}
      158          )
```

**Decisão**: pendente

### 38 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_oud/schema.py:250` · **Effort**: 7min

> Refactor this function to reduce its Cognitive Complexity from 17 to the 15 allowed.

```python
      246                  f"Invalid OUD OID format: {oid} (must be numeric RFC OID or end with -oid suffix)"
      247              )
      248          return r[bool].ok(is_valid_oud_oid)
      249  
>>>   250      def _validate_objectclass_oid_and_sup(
      251          self, oc: m.Ldif.SchemaObjectClass
      252      ) -> p.Result[m.Ldif.SchemaObjectClass]:
      253          """Validate ObjectClass OID and SUP OID formats."""
      254          if oc and oc.oid:
```

**Decisão**: pendente

### 39 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/_rfc/schema.py:18` · **Effort**: 6min

> Refactor this function to reduce its Cognitive Complexity from 16 to the 15 allowed.

```python
       14      """RFC 4512 Compliant Schema Server - STRICT Implementation."""
       15  
       16      _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
       17  
>>>    18      def __new__(
       19          cls,
       20          schema_service: p.Ldif.SchemaServer | None = None,
       21          parent_server: p.Ldif.SchemaServer | None = None,
       22          **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
```

**Decisão**: pendente

### 40 · 🟠 CRITICAL · CODE_SMELL · `python:S5797`
**Local**: `src/flext_ldif/servers/openldap1.py:216` · **Effort**: 2min

> Replace this expression; used as a condition it will always be constant.

```python
      212              if attr_data.syntax:
      213                  attr_str += f" SYNTAX {attr_data.syntax}"
      214              if attr_data.equality:
      215                  attr_str += f" EQUALITY {attr_data.equality}"
>>>   216              if attr_data.single_value or False:
      217                  attr_str += " SINGLE-VALUE"
      218              attr_str += " )"
      219              return r[str].ok(attr_str)
      220  
```

**Decisão**: pendente

### 41 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/servers/relaxed.py:557` · **Effort**: 9min

> Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.

```python
      553          def process_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
      554              """Process entry for relaxed mode."""
      555              return r[m.Ldif.Entry].ok(entry)
      556  
>>>   557          def _adapted_parse_entry_relaxed(
      558              self, entry_content: str
      559          ) -> p.Result[m.Ldif.Entry]:
      560              """Parse entry content in relaxed mode (extracted from _parse_content)."""
      561              dn: str = ""
```

**Decisão**: pendente

### 42 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldif/services/conversion_schema.py:31` · **Effort**: 13min

> Refactor this function to reduce its Cognitive Complexity from 23 to the 15 allowed.

```python
       27          entry: m.Ldif.Entry,
       28      ) -> p.Result[t.Ldif.ConvertedModel]:
       29          """Convert an entry through the concrete conversion facade."""
       30  
>>>    31      def _convert_schema_model_via_entry(
       32          self,
       33          source_server: p.Ldif.ServerServer,
       34          target_server: p.Ldif.ServerServer,
       35          item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
```

**Decisão**: pendente

### 43 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8264`
**Local**: `.github/workflows/docs.yml:18` · **Effort**: 5min

> Move this read permission from workflow level to job level.

```yaml
       14        - ".github/workflows/docs.yml"
       15    workflow_dispatch:
       16  
       17  permissions:
>>>    18    contents: read
       19    pages: write
       20    id-token: write
       21  
       22  concurrency:
```

**Decisão**: pendente

### 44 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8233`
**Local**: `.github/workflows/docs.yml:19` · **Effort**: 5min

> Move this write permission from workflow level to job level.

```yaml
       15    workflow_dispatch:
       16  
       17  permissions:
       18    contents: read
>>>    19    pages: write
       20    id-token: write
       21  
       22  concurrency:
       23    group: pages
```

**Decisão**: pendente

### 45 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8233`
**Local**: `.github/workflows/docs.yml:20` · **Effort**: 5min

> Move this write permission from workflow level to job level.

```yaml
       16  
       17  permissions:
       18    contents: read
       19    pages: write
>>>    20    id-token: write
       21  
       22  concurrency:
       23    group: pages
       24    cancel-in-progress: false
```

**Decisão**: pendente

### 46 · 🟡 MAJOR · CODE_SMELL · `python:S3358`
**Local**: `examples/05_schema_operations.py:223` · **Effort**: 5min

> Extract this nested conditional expression into an independent statement.

```python
      219                      attrs_dict[attr_name] = attr_values
      220          entry_dn: str = (
      221              ldif_entry.dn.value
      222              if ldif_entry.dn is not None and hasattr(ldif_entry.dn, "value")
>>>   223              else str(ldif_entry.dn)
      224              if ldif_entry.dn is not None
      225              else ""
      226          )
      227          migrate_result = m.Ldif.Entry.create(dn=entry_dn, attributes=attrs_dict)
```

**Decisão**: pendente

### 47 · 🟡 MAJOR · VULNERABILITY · `text:S8565`
**Local**: `pyproject.toml:-` · **Effort**: 5min

> Dependency versions are not predictable if the lock file (uv.lock, poetry.lock, pdm.lock or pylock.toml) is missing.

**Decisão**: pendente

### 48 · 🟡 MAJOR · CODE_SMELL · `python:S8786`
**Local**: `src/flext_ldif/_constants/base.py:124` · **Effort**: 20min

> Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.

```python
      120      SCHEMA_OBJECTCLASS_KIND: Final[str] = "\\b(ABSTRACT|STRUCTURAL|AUXILIARY)\\b"
      121      SCHEMA_OBJECTCLASS_SUP: Final[str] = (
      122          "SUP\\s+(?:\\(\\s*([^)]+)\\s*\\)|'(\\w+)'|(\\w+))"
      123      )
>>>   124      SCHEMA_OBJECTCLASS_MUST: Final[str] = "MUST\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
      125      SCHEMA_OBJECTCLASS_MAY: Final[str] = "MAY\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
      126      ATTRIBUTE_NAME: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*$"
      127      ATTRIBUTE_OPTION: Final[str] = ";[a-zA-Z][a-zA-Z0-9-_]*"
      128      BINARY_CHAR_PATTERN: Final[str] = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\xff]"
```

**Decisão**: pendente

### 49 · 🟡 MAJOR · CODE_SMELL · `python:S8786`
**Local**: `src/flext_ldif/_constants/base.py:125` · **Effort**: 20min

> Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.

```python
      121      SCHEMA_OBJECTCLASS_SUP: Final[str] = (
      122          "SUP\\s+(?:\\(\\s*([^)]+)\\s*\\)|'(\\w+)'|(\\w+))"
      123      )
      124      SCHEMA_OBJECTCLASS_MUST: Final[str] = "MUST\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
>>>   125      SCHEMA_OBJECTCLASS_MAY: Final[str] = "MAY\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
      126      ATTRIBUTE_NAME: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*$"
      127      ATTRIBUTE_OPTION: Final[str] = ";[a-zA-Z][a-zA-Z0-9-_]*"
      128      BINARY_CHAR_PATTERN: Final[str] = "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\xff]"
      129      NUMERIC_OID_PATTERN: Final[str] = "^\\d+(\\.\\d+)*$"
```

**Decisão**: pendente

### 50 · 🟡 MAJOR · CODE_SMELL · `python:S5869`
**Local**: `src/flext_ldif/_constants/base.py:141` · **Effort**: 5min

> Remove duplicates in this character class.

```python
      137      ATTRIBUTE_NAME_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_NAME)
      138      ATTRIBUTE_OPTION_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_OPTION)
      139      BINARY_CHAR_RE: ClassVar[t.RegexPattern] = re.compile(BINARY_CHAR_PATTERN)
      140      DN_COMPONENT_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   141          r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$", re.IGNORECASE
      142      )
      143      NUMERIC_OID_RE: ClassVar[t.RegexPattern] = re.compile(NUMERIC_OID_PATTERN)
      144      SCHEMA_X_EXTENSION_RE: ClassVar[t.RegexPattern] = re.compile(
      145          SCHEMA_X_EXTENSION, re.IGNORECASE
```

**Decisão**: pendente

### 51 · 🟡 MAJOR · CODE_SMELL · `python:S5869`
**Local**: `src/flext_ldif/_constants/base.py:141` · **Effort**: 5min

> Remove duplicates in this character class.

```python
      137      ATTRIBUTE_NAME_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_NAME)
      138      ATTRIBUTE_OPTION_RE: ClassVar[t.RegexPattern] = re.compile(ATTRIBUTE_OPTION)
      139      BINARY_CHAR_RE: ClassVar[t.RegexPattern] = re.compile(BINARY_CHAR_PATTERN)
      140      DN_COMPONENT_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   141          r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$", re.IGNORECASE
      142      )
      143      NUMERIC_OID_RE: ClassVar[t.RegexPattern] = re.compile(NUMERIC_OID_PATTERN)
      144      SCHEMA_X_EXTENSION_RE: ClassVar[t.RegexPattern] = re.compile(
      145          SCHEMA_X_EXTENSION, re.IGNORECASE
```

**Decisão**: pendente

### 52 · 🟡 MAJOR · CODE_SMELL · `python:S8786`
**Local**: `src/flext_ldif/_constants/base.py:210` · **Effort**: 20min

> Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.

```python
      206      SCHEMA_X_ORIGIN_RE: ClassVar[t.RegexPattern] = re.compile(
      207          r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
      208      )
      209      SCHEMA_NAME_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   210          r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?"
      211      )
      212      SCHEMA_NAME_MULTIPLE_RE: ClassVar[t.RegexPattern] = re.compile(
      213          r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])"
      214      )
```

**Decisão**: pendente

### 53 · 🟡 MAJOR · BUG · `python:S5855`
**Local**: `src/flext_ldif/_constants/base.py:217` · **Effort**: 5min

> Remove or rework this redundant alternative.

```python
      213          r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])"
      214      )
      215      QUOTED_SPACE_QUOTE_RE: ClassVar[t.RegexPattern] = re.compile(r"[\"']\s+([\"'])")
      216      LDIF_ATTR_TYPES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   217          r"(attributetypes|attributeTypes):", re.IGNORECASE
      218      )
      219      LDIF_OBJECTCLASSES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
      220          r"(objectclasses|objectClasses):", re.IGNORECASE
      221      )
```

**Decisão**: pendente

### 54 · 🟡 MAJOR · BUG · `python:S5855`
**Local**: `src/flext_ldif/_constants/base.py:220` · **Effort**: 5min

> Remove or rework this redundant alternative.

```python
      216      LDIF_ATTR_TYPES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
      217          r"(attributetypes|attributeTypes):", re.IGNORECASE
      218      )
      219      LDIF_OBJECTCLASSES_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   220          r"(objectclasses|objectClasses):", re.IGNORECASE
      221      )
      222      ACI_MACRO_RE: ClassVar[t.RegexPattern] = re.compile(r"\(\$dn\)|\[\$dn\]|\(\$attr\.")
      223      ACL_NAME_QUOTED_RE: ClassVar[t.RegexPattern] = re.compile(r'acl\s+"[^"]*"')
      224      DN_SPLIT_OPTIONAL_SPACE_RE: ClassVar[t.RegexPattern] = re.compile(r"\s*,\s*")
```

**Decisão**: pendente

### 55 · 🟡 MAJOR · CODE_SMELL · `python:S107`
**Local**: `src/flext_ldif/_models/domain_entry.py:884` · **Effort**: 20min

> Method "create" has 20 parameters, which is greater than the 13 authorized.

```python
      880                      metadata.extensions[f"unconverted_{key}"] = str(value)
      881  
      882          @classmethod
      883          def create(
>>>   884              cls,
      885              dn: str | mdn.DN,
      886              attributes: t.MutableAttributeMapping | mda.Attributes,
      887              metadata: mdm.ServerMetadata | None = None,
      888              acls: t.MutableSequenceOf[mdac.Acl] | None = None,
```

**Decisão**: pendente

### 56 · 🟡 MAJOR · CODE_SMELL · `python:S107`
**Local**: `src/flext_ldif/_models/domain_entry.py:944` · **Effort**: 20min

> Method "_build_entry_data" has 20 parameters, which is greater than the 13 authorized.

```python
      940                  return fail_result
      941  
      942          @classmethod
      943          def _build_entry_data(
>>>   944              cls,
      945              dn: str | mdn.DN,
      946              attributes: t.MutableAttributeMapping | mda.Attributes,
      947              metadata: mdm.ServerMetadata | None,
      948              acls: t.MutableSequenceOf[mdac.Acl] | None,
```

**Decisão**: pendente

### 57 · 🟡 MAJOR · BUG · `pythonbugs:S2583`
**Local**: `src/flext_ldif/_utilities/acl.py:521` · **Effort**: 15min

> Fix this condition that always evaluates to true.

```python
      517          """Extract conversion comments from metadata extensions."""
      518          if not extensions:
      519              return []
      520          converted_from_value = (
>>>   521              extensions.get(converted_from_key) if extensions else None
      522          )
      523          if not converted_from_value:
      524              return []
      525          comments_value: t.Ldif.MetadataCarrierValue | None = (
```

**Decisão**: pendente

### 58 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/_utilities/collection_ldif.py:60` · **Effort**: 5min

> Either remove or fill this block of code.

```python
       56              match (value, other):
       57                  case [str() as value_str, str() as other_str]:
       58                      return normalize_single(value_str) == normalize_single(other_str)
       59                  case _:
>>>    60                      pass
       61          match value:
       62              case str() as value_str:
       63                  result = normalize_single(value_str)
       64              case list() | tuple() as seq_value:
```

**Decisão**: pendente

### 59 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/_utilities/entry.py:672` · **Effort**: 5min

> Either remove or fill this block of code.

```python
      668                              normalized_value = (
      669                                  "1" if normalized_value.upper() == "TRUE" else "0"
      670                              )
      671                          case _:
>>>   672                              pass
      673                  str_values.append(normalized_value)
      674              result[attr_name] = str_values
      675          return result
      676  
```

**Decisão**: pendente

### 60 · 🟡 MAJOR · CODE_SMELL · `python:S3358`
**Local**: `src/flext_ldif/api.py:84` · **Effort**: 5min

> Extract this nested conditional expression into an independent statement.

```python
       80          """Create a categorization service bound to the facade registry."""
       81          resolved_base_dn = (
       82              base_dn
       83              if base_dn is not None
>>>    84              else options.base_dn
       85              if options is not None
       86              else None
       87          )
       88          categorization = FlextLdifCategorization(
```

**Decisão**: pendente

### 61 · 🟡 MAJOR · VULNERABILITY · `python:S2068`
**Local**: `src/flext_ldif/constants.py:458` · **Effort**: 30min

> "password" detected here, review this potentially hard-coded credential.

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

**Decisão**: pendente

### 62 · 🟡 MAJOR · CODE_SMELL · `python:S3358`
**Local**: `src/flext_ldif/servers/_oud/acl.py:291` · **Effort**: 5min

> Extract this nested conditional expression into an independent statement.

```python
      287          attr_subject_types = {"dn_attr", "guid_attr", "group_attr"}
      288          subject_type = (
      289              source_subject_type
      290              if source_subject_type in attr_subject_types
>>>   291              else (subject.subject_type if subject else source_subject_type)
      292          ) or "self"
      293          if subject_type == FlextLdifServersOudConstants.ACL_SUBJECT_TYPE_BIND_RULES:
      294              subject_value_lower = (
      295                  (subject.subject_value or "").lower() if subject else ""
```

**Decisão**: pendente

### 63 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/servers/_oud/acl.py:310` · **Effort**: 5min

> Either remove or fill this block of code.

```python
      306                      in subject_value_lower
      307                  ):
      308                      subject_type = "group"
      309                  case _:
>>>   310                      pass
      311          subject_value = (
      312              subject.subject_value if subject else None
      313          ) or self._extension_get_str(ext, "acl_original_subject_value")
      314          if not subject_value:
```

**Decisão**: pendente

### 64 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/servers/_rfc/schema.py:593` · **Effort**: 5min

> Either remove or fill this block of code.

```python
      589                  FlextLdifServersBaseSchema.validate_and_track_oid(
      590                      metadata_extensions, objectclass_oid_str, "objectClass"
      591                  )
      592              case _:
>>>   593                  pass
      594          objectclass_sup_oid = parsed.get("sup")
      595          match objectclass_sup_oid:
      596              case None:
      597                  FlextLdifServersBaseSchema.validate_and_track_oid(
```

**Decisão**: pendente

### 65 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/servers/_rfc/schema.py:605` · **Effort**: 5min

> Either remove or fill this block of code.

```python
      601                  FlextLdifServersBaseSchema.validate_and_track_oid(
      602                      metadata_extensions, objectclass_sup_oid_str, "objectClass SUP"
      603                  )
      604              case _:
>>>   605                  pass
      606          must_list = self._to_string_list(parsed.get("must"))
      607          self._validate_oid_list(must_list, "MUST", metadata_extensions)
      608          may_list = self._to_string_list(parsed.get("may"))
      609          self._validate_oid_list(may_list, "MAY", metadata_extensions)
```

**Decisão**: pendente

### 66 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/servers/_rfc/schema.py:661` · **Effort**: 5min

> Either remove or fill this block of code.

```python
      657                      FlextLdifServersBaseSchema.validate_and_track_oid(
      658                          metadata_extensions, oid_str, f"objectClass {oid_type}[{idx}]"
      659                      )
      660                  case _:
>>>   661                      pass
      662  
      663      @override
      664      def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
      665          """Write attribute to RFC-compliant string format (internal)."""
```

**Decisão**: pendente

### 67 · 🟡 MAJOR · BUG · `pythonbugs:S2583`
**Local**: `src/flext_ldif/servers/ad.py:325` · **Effort**: 15min

> Fix this condition that always evaluates to true.

```python
      321              """Write Active Directory ACL content."""
      322              if not acl_data.raw_acl:
      323                  return r[str].fail("Active Directory ACL write requires raw_acl value")
      324              acl_attribute = FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME
>>>   325              if acl_data.raw_acl:
      326                  return r[str].ok(f"{acl_attribute}: {acl_data.raw_acl}")
      327              return r[str].ok(f"{acl_attribute}:")
      328  
      329      class Entry(FlextLdifServersRfc.Entry):
```

**Decisão**: pendente

### 68 · 🟡 MAJOR · CODE_SMELL · `python:S5869`
**Local**: `src/flext_ldif/servers/openldap.py:111` · **Effort**: 5min

> Remove duplicates in this character class.

```python
      107              "person",
      108              "organizationalPerson",
      109              "inetOrgPerson",
      110          ])
>>>   111          SCHEMA_OPENLDAP_OLC_PATTERN: ClassVar[str] = "\\bolc[A-Z][a-zA-Z]*\\b"
      112          SCHEMA_OPENLDAP_OLC_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
      113              SCHEMA_OPENLDAP_OLC_PATTERN, re.IGNORECASE
      114          )
      115          ACL_BY_PATTERN: ClassVar[str] = "by\\s+([^\\s]+)\\s+([^\\s]+)"
```

**Decisão**: pendente

### 69 · 🟡 MAJOR · CODE_SMELL · `python:S8786`
**Local**: `src/flext_ldif/servers/openldap.py:122` · **Effort**: 20min

> Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.

```python
      118          )
      119          ACL_DEFAULT_NAME: ClassVar[str] = "access"
      120          ACL_INDEX_PATTERN: ClassVar[str] = "^\\{(\\d+)\\}\\s*(.+)"
      121          ACL_INDEX_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(ACL_INDEX_PATTERN)
>>>   122          ACL_TO_BY_PATTERN: ClassVar[str] = "^to\\s+(.+?)\\s+by\\s+"
      123          ACL_TO_BY_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
      124              ACL_TO_BY_PATTERN, re.IGNORECASE
      125          )
      126          ACL_ATTRS_PATTERN: ClassVar[str] = (
```

**Decisão**: pendente

### 70 · 🟡 MAJOR · CODE_SMELL · `python:S8786`
**Local**: `src/flext_ldif/servers/openldap1.py:98` · **Effort**: 20min

> Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.

```python
       94          ACL_ACCESS_TO_PATTERN: ClassVar[str] = "^\\s*access\\s+to\\s+"
       95          ACL_ACCESS_TO_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       96              ACL_ACCESS_TO_PATTERN, re.IGNORECASE
       97          )
>>>    98          ACL_TO_BY_PATTERN: ClassVar[str] = "^to\\s+(.+?)\\s+by\\s+"
       99          ACL_TO_BY_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
      100              ACL_TO_BY_PATTERN, re.IGNORECASE
      101          )
      102          ACL_SUBJECT_TYPE_USERDN: ClassVar[str] = "userdn"
```

**Decisão**: pendente

### 71 · 🟡 MAJOR · CODE_SMELL · `python:S108`
**Local**: `src/flext_ldif/services/acl.py:67` · **Effort**: 5min

> Either remove or fill this block of code.

```python
       63              matched_acl=None,
       64              message="No ACLs to evaluate - access denied by default",
       65          )
       66          if not acls:
>>>    67              pass
       68          elif not required_perms:
       69              evaluation = m.Ldif.AclEvaluationResult(
       70                  granted=True,
       71                  matched_acl=u.Ldif.as_acl(acls[0]),
```

**Decisão**: pendente

### 72 · 🟡 MAJOR · CODE_SMELL · `python:S3358`
**Local**: `src/flext_ldif/services/categorization.py:213` · **Effort**: 5min

> Extract this nested conditional expression into an independent statement.

```python
      209                  entry,
      210                  category=category,
      211                  mark_rejected=(
      212                      c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
>>>   213                      match_reason
      214                      if match_reason is not None
      215                      else c.Ldif.REJECTION_REASON_NO_CATEGORY_MATCH,
      216                  )
      217                  if is_rejected
```

**Decisão**: pendente

### 73 · 🟡 MAJOR · CODE_SMELL · `python:S1854`
**Local**: `src/flext_ldif/services/conversion_acl_preserve.py:98` · **Effort**: 1min

> Remove this assignment to local variable 'mapping_type'; the value is never used.

```python
       94                      "oud_to_oid",
       95                      u.Ldif.map_oud_to_oid_permissions,
       96                  ),
       97              }.get(server_pair)
>>>    98              mapping_type = "none"
       99              replacement_permissions: m.Ldif.AclPermissions | None = None
      100              match permission_mapping:
      101                  case (mapping_type, permission_mapper):
      102                      mapped_perms = permission_mapper(
```

**Decisão**: pendente

### 74 · 🟡 MAJOR · BUG · `pythonbugs:S2583`
**Local**: `src/flext_ldif/services/filters.py:46` · **Effort**: 15min

> Fix this condition that always evaluates to true.

```python
       42      ) -> str | None:
       43          """Extract OID from schema attribute value."""
       44          if not values:
       45              return None
>>>    46          value = values[0] if values else ""
       47          value = value.strip()
       48          if value.startswith("("):
       49              parts = value[1:].strip().split()
       50              if parts:
```

**Decisão**: pendente

### 75 · ⚪ MINOR · CODE_SMELL · `python:S7504`
**Local**: `conftest.py:20` · **Effort**: 5min

> Remove this unnecessary `list()` call on an already iterable object.

```python
       16      if (
       17          existing_package is None
       18          or Path(getattr(existing_package, "__file__", "")).resolve() != init_file
       19      ):
>>>    20          for module_name in list(sys.modules):
       21              if module_name == package_name or module_name.startswith(
       22                  f"{package_name}."
       23              ):
       24                  sys.modules.pop(module_name, None)
```

**Decisão**: pendente

### 76 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/_constants/base.py:204` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
      200      SCHEMA_SUP_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
      201          r"SUP\s+([^\s]+)", re.IGNORECASE
      202      )
      203      SCHEMA_SYNTAX_LOOSE_RE: ClassVar[t.RegexPattern] = re.compile(
>>>   204          r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?", re.IGNORECASE
      205      )
      206      SCHEMA_X_ORIGIN_RE: ClassVar[t.RegexPattern] = re.compile(
      207          r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)", re.IGNORECASE
      208      )
```

**Decisão**: pendente

### 77 · ⚪ MINOR · CODE_SMELL · `python:S116`
**Local**: `src/flext_ldif/_utilities/transformers.py:20` · **Effort**: 2min

> Rename this field "NormalizeDnTransformer" to match the regular expression ^[_a-z][_a-z0-9]*$.

```python
       16  
       17  class FlextLdifUtilitiesTransformers:
       18      """Concrete transformer classes for LDIF entry pipelines."""
       19  
>>>    20      NormalizeDnTransformer: ClassVar[type[FlextLdifUtilitiesNormalizeDnTransformer]] = (
       21          FlextLdifUtilitiesNormalizeDnTransformer
       22      )
       23      NormalizeAttrsTransformer: ClassVar[
       24          type[FlextLdifUtilitiesNormalizeAttrsTransformer]
```

**Decisão**: pendente

### 78 · ⚪ MINOR · CODE_SMELL · `python:S116`
**Local**: `src/flext_ldif/_utilities/transformers.py:23` · **Effort**: 2min

> Rename this field "NormalizeAttrsTransformer" to match the regular expression ^[_a-z][_a-z0-9]*$.

```python
       19  
       20      NormalizeDnTransformer: ClassVar[type[FlextLdifUtilitiesNormalizeDnTransformer]] = (
       21          FlextLdifUtilitiesNormalizeDnTransformer
       22      )
>>>    23      NormalizeAttrsTransformer: ClassVar[
       24          type[FlextLdifUtilitiesNormalizeAttrsTransformer]
       25      ] = FlextLdifUtilitiesNormalizeAttrsTransformer
       26  
       27      class Normalize:
```

**Decisão**: pendente

### 79 · ⚪ MINOR · CODE_SMELL · `python:S5713`
**Local**: `src/flext_ldif/servers/_base/schema.py:305` · **Effort**: 1min

> Remove this redundant Exception class; it derives from another which is already caught.

```python
      301              c.ValidationError,
      302              ValueError,
      303              KeyError,
      304              AttributeError,
>>>   305              UnicodeDecodeError,
      306              struct.error,
      307          ):
      308              pass
      309          try:
```

**Decisão**: pendente

### 80 · ⚪ MINOR · CODE_SMELL · `python:S5713`
**Local**: `src/flext_ldif/servers/_base/schema.py:319` · **Effort**: 1min

> Remove this redundant Exception class; it derives from another which is already caught.

```python
      315              c.ValidationError,
      316              ValueError,
      317              KeyError,
      318              AttributeError,
>>>   319              UnicodeDecodeError,
      320              struct.error,
      321          ):
      322              pass
      323          return None
```

**Decisão**: pendente

### 81 · ⚪ MINOR · CODE_SMELL · `python:S7504`
**Local**: `src/flext_ldif/servers/_oid/entry.py:539` · **Effort**: 5min

> Remove this unnecessary `list()` call on an already iterable object.

```python
      535          }
      536          substr_map = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC
      537          syntax_map = FlextLdifServersOidConstants.SYNTAX_OID_TO_RFC
      538          schema_fields = {"attributetypes", "objectclasses", "matchingrules"}
>>>   539          for attr_name in list(attrs):
      540              if attr_name.lower() not in schema_fields:
      541                  continue
      542              values = attrs[attr_name]
      543              updated: list[str] = []
```

**Decisão**: pendente

### 82 · ⚪ MINOR · CODE_SMELL · `python:S7504`
**Local**: `src/flext_ldif/servers/_oid/entry.py:677` · **Effort**: 5min

> Remove this unnecessary `list()` call on an already iterable object.

```python
      673          boolean_attr_names = {
      674              attr.lower() for attr in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
      675          }
      676          restored_attrs = dict(entry_data.attributes.attributes)
>>>   677          for attr_name in list(restored_attrs.keys()):
      678              if attr_name.lower() not in boolean_attr_names:
      679                  continue
      680              conv_data = boolean_conversions.get(attr_name, {})
      681              if conv_data:
```

**Decisão**: pendente

### 83 · ⚪ MINOR · CODE_SMELL · `python:S7508`
**Local**: `src/flext_ldif/servers/ad.py:359` · **Effort**: 5min

> Remove this redundant call.

```python
      355                  for marker in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_MARKERS
      356              ):
      357                  return True
      358              raw_object_classes = attributes.get(c.Ldif.DictKeys.OBJECTCLASS, [])
>>>   359              object_classes = list(raw_object_classes)
      360              normalized_object_classes: t.MutableSequenceOf[str] = list(object_classes)
      361              return any(
      362                  oc.lower() in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
      363                  for oc in normalized_object_classes
```

**Decisão**: pendente

### 84 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/servers/relaxed.py:32` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
       28          ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
       29          OID_PATTERN: ClassVar[t.Ldif.RegexPattern] = re.compile(
       30              r"\(\s*([0-9a-zA-Z._\-]+)"
       31          )
>>>    32          OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
       33          OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       34              OID_NUMERIC_WITH_PAREN
       35          )
       36          OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
```

**Decisão**: pendente

### 85 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/servers/relaxed.py:32` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
       28          ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
       29          OID_PATTERN: ClassVar[t.Ldif.RegexPattern] = re.compile(
       30              r"\(\s*([0-9a-zA-Z._\-]+)"
       31          )
>>>    32          OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
       33          OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       34              OID_NUMERIC_WITH_PAREN
       35          )
       36          OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
```

**Decisão**: pendente

### 86 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/servers/relaxed.py:36` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
       32          OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
       33          OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       34              OID_NUMERIC_WITH_PAREN
       35          )
>>>    36          OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
       37          OID_NUMERIC_ANYWHERE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       38              OID_NUMERIC_ANYWHERE
       39          )
       40          OID_ALPHANUMERIC_RELAXED: ClassVar[str] = "\\(\\s*([a-zA-Z0-9._-]+)"
```

**Decisão**: pendente

### 87 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/servers/relaxed.py:36` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
       32          OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
       33          OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       34              OID_NUMERIC_WITH_PAREN
       35          )
>>>    36          OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
       37          OID_NUMERIC_ANYWHERE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       38              OID_NUMERIC_ANYWHERE
       39          )
       40          OID_ALPHANUMERIC_RELAXED: ClassVar[str] = "\\(\\s*([a-zA-Z0-9._-]+)"
```

**Decisão**: pendente

### 88 · ⚪ MINOR · CODE_SMELL · `python:S6353`
**Local**: `src/flext_ldif/servers/relaxed.py:36` · **Effort**: 5min

> Use concise character class syntax '\d' instead of '[0-9]'.

```python
       32          OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
       33          OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       34              OID_NUMERIC_WITH_PAREN
       35          )
>>>    36          OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
       37          OID_NUMERIC_ANYWHERE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
       38              OID_NUMERIC_ANYWHERE
       39          )
       40          OID_ALPHANUMERIC_RELAXED: ClassVar[str] = "\\(\\s*([a-zA-Z0-9._-]+)"
```

**Decisão**: pendente

### 89 · ⚪ MINOR · CODE_SMELL · `python:S5685`
**Local**: `src/flext_ldif/services/acl.py:78` · **Effort**: 10min

> Move this assignment out of the argument list; ":=" operator is confusing in this context.

```python
       74          else:
       75              found_result = u.find(
       76                  acls,
       77                  predicate=lambda acl: (
>>>    78                      (permissions := acl.permissions) is not None
       79                      and all(getattr(permissions, perm) for perm in required_perms)
       80                  ),
       81              )
       82              if found_result.success:
```

**Decisão**: pendente

### 90 · ⚪ MINOR · CODE_SMELL · `python:S7504`
**Local**: `src/flext_ldif/services/filters.py:178` · **Effort**: 5min

> Remove this unnecessary `list()` call on an already iterable object.

```python
      174          updated_attrs: dict[str, list[str]] = {
      175              k: list(v) for k, v in attrs_dict.items()
      176          }
      177          changed = False
>>>   178          for attr_name in list(updated_attrs):
      179              oid_set = allowed_value_oids.get(attr_name.lower())
      180              if oid_set is None:
      181                  continue
      182              original = updated_attrs[attr_name]
```

**Decisão**: pendente

### 91 · ⚪ MINOR · CODE_SMELL · `python:S8714`
**Local**: `tests/integration/fixtures.py:119` · **Effort**: 5min

> Remove this try/except block and let the test fail naturally if an exception is raised.

```python
      115      srv = u.Tests.create_server_from_url(server_url)
      116      conn = u.Tests.create_connection(
      117          srv, user=bind_dn, password=password, auto_bind=False
      118      )
>>>   119      try:
      120          bind_ok: bool = conn.bind()
      121          if not bind_ok:
      122              pytest.fail(
      123                  f"LDAP server not available at {server_url} for bind_dn={bind_dn}"
```

**Decisão**: pendente
