"""Base LDIF structural contracts."""

from __future__ import annotations

from collections.abc import (
    KeysView,
    Mapping,
    MutableMapping,
    Sequence,
    ValuesView,
)
from pathlib import Path
from typing import ClassVar, Literal, Protocol, Self, runtime_checkable

from flext_cli import p, t
from flext_ldif.constants import c

# NOTE (multi-agent, mro-0ftd.3.7.2): this lowest protocol facet deliberately
# depends only on upstream declarations and constants so no public facade can
# re-enter it while the LDIF protocol namespace is being composed.


@runtime_checkable
class FlextLdifProtocolsBase(Protocol):
    """Base LDIF protocols shared across utilities, services, and servers."""

    @runtime_checkable
    class ValidationService(Protocol):
        """Contract for entry validation helpers."""

        def validate_attribute_name(self, name: str) -> p.Result[bool]:
            """Return whether the attribute name is valid."""
            ...

        def validate_objectclass_name(self, name: str) -> p.Result[bool]:
            """Return whether the objectClass name is valid."""
            ...

    @runtime_checkable
    class ServerDetectionService(Protocol):
        """Contract for LDIF server type detection helpers."""

        def detect_server_type(
            self,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
            max_lines: int | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ServerDetectionResult]:
            """Detect LDAP server type from LDIF file or content."""
            ...

    @runtime_checkable
    class ServerDetectionResult(Protocol):
        """Detected server type returned by the public detection service."""

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes:
            """The detected LDAP server type."""
            ...

    @runtime_checkable
    class CategoryRules(p.Model, Protocol):
        """Validated category-rule capabilities consumed by categorization."""

        @property
        def category_markers(self) -> t.FrozensetMapping:
            """Normalized category markers keyed by category."""
            ...

    @runtime_checkable
    class WhitelistRules(p.Model, Protocol):
        """Validated schema-whitelist capabilities consumed by filtering."""

        @property
        def has_oid_filters(self) -> bool:
            """Whether any schema OID filter is configured."""
            ...

        @property
        def schema_oid_filters(self) -> t.FrozensetMapping:
            """Configured OID filters keyed by schema attribute."""
            ...

    @runtime_checkable
    class MigrateOptions(p.Model, Protocol):
        """Public migration options without a concrete model dependency."""

        @property
        def base_dn(self) -> str | None: ...

        @property
        def output_filename(self) -> str | None: ...

        @property
        def forbidden_attributes(self) -> Sequence[str] | None: ...

        @property
        def forbidden_objectclasses(self) -> Sequence[str] | None: ...

        @property
        def categorization_rules(
            self,
        ) -> FlextLdifProtocolsBase.CategoryRules | None: ...

        @property
        def schema_whitelist_rules(
            self,
        ) -> FlextLdifProtocolsBase.WhitelistRules | None: ...

    @runtime_checkable
    class AclEvaluationResult(Protocol):
        """Outcome of evaluating ACLs against required permissions."""

        @property
        def granted(self) -> bool: ...

        @property
        def matched_acl(self) -> FlextLdifProtocolsBase.Acl | None: ...

        @property
        def message(self) -> str: ...

    @runtime_checkable
    class ProcessEntriesOptions(p.Model, Protocol):
        """Validated controls for sequential or parallel entry processing."""

        @property
        def processor_name(self) -> Literal["transform", "validate"]: ...

        @property
        def parallel(self) -> bool: ...

        @property
        def batch_size(self) -> int: ...

        @property
        def max_workers(self) -> int: ...

    @runtime_checkable
    class ProcessingResult(Protocol):
        """Observable result of processing one entry."""

        @property
        def dn(self) -> str: ...

        @property
        def attributes(self) -> t.StrSequenceMapping: ...

    @runtime_checkable
    class DynamicCounts(Protocol):
        """Read-only count collection exposed by statistics results."""

        def get(self, key: str, default: int | None = None) -> int | None: ...

        def items(self) -> Sequence[tuple[str, int]]: ...

    @runtime_checkable
    class EntriesStatistics(Protocol):
        """Aggregate distributions calculated for a batch of entries."""

        @property
        def total_entries(self) -> int: ...

        @property
        def object_class_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts: ...

        @property
        def server_type_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts: ...

    @runtime_checkable
    class FlexibleCategories(Protocol):
        """Read-only categorized entry groups."""

        @property
        def categories(
            self,
        ) -> Mapping[str, Sequence[FlextLdifProtocolsBase.Entry]]: ...

    @runtime_checkable
    class DNStatistics(Protocol):
        """Statistics about DN normalization and validation."""

        original_dn: str
        cleaned_dn: str
        normalized_dn: str
        transformations: t.StrSequence
        validation_warnings: t.StrSequence
        validation_errors: t.StrSequence
        was_transformed: bool

    @runtime_checkable
    class DN(Protocol):
        """Distinguished Name value contract."""

        @property
        def value(self) -> str:
            """The DN string value."""
            ...

    @runtime_checkable
    class Attributes(Protocol):
        """Attribute container contract used by entry utilities."""

        @property
        def attributes(self) -> MutableMapping[str, t.MutableSequenceOf[str]]:
            """The underlying attribute mapping."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property members the OUD
        # round-trip restore helper reads (transform.py restore_entry_from_metadata);
        # concrete m.Ldif.Attributes carries these fields (domain_attributes.py:38/44).
        @property
        def attribute_metadata(self) -> Mapping[str, t.MutableAttributeMapping]:
            """Per-attribute metadata (category/hidden status)."""
            ...

        @property
        def metadata(self) -> t.MutableJsonMapping | None:
            """Ordering/format preservation metadata."""
            ...

        def get(
            self,
            key: str,
            default: t.MutableSequenceOf[str] | None = None,
        ) -> t.MutableSequenceOf[str]:
            """Return attribute values with optional default."""
            ...

        def items(self) -> t.MutableSequenceOf[tuple[str, t.MutableSequenceOf[str]]]:
            """Return attribute items as a list of tuples."""
            ...

        def keys(self) -> KeysView[str]:
            """Return attribute names view."""
            ...

        def values(self) -> ValuesView[t.MutableSequenceOf[str]]:
            """Return attribute value lists view."""
            ...

    @runtime_checkable
    class AttributeTransformation(Protocol):
        """Attribute transformation audit record."""

        original_name: str
        target_name: str | None
        original_values: t.MutableSequenceOf[str]
        target_values: t.MutableSequenceOf[str] | None
        transformation_type: str
        reason: str

    @runtime_checkable
    class AclPermissions(Protocol):
        """ACL permission flag set."""

        @property
        def read(self) -> bool:
            """Whether read is allowed."""
            ...

        @property
        def write(self) -> bool:
            """Whether write is allowed."""
            ...

        @property
        def search(self) -> bool:
            """Whether search is allowed."""
            ...

        @property
        def compare(self) -> bool:
            """Whether compare is allowed."""
            ...

    @runtime_checkable
    class AclTarget(Protocol):
        """ACL target descriptor."""

        @property
        def target_dn(self) -> str:
            """The target DN expression."""
            ...

        @property
        def attributes(self) -> t.MutableSequenceOf[str]:
            """The target attribute names."""
            ...

    @runtime_checkable
    class AclSubject(Protocol):
        """ACL subject descriptor."""

        @property
        def subject_type(self) -> str:
            """The subject type."""
            ...

        @property
        def subject_value(self) -> str:
            """The subject value."""
            ...

    @runtime_checkable
    class ValidationMetadata(Protocol):
        """Validation result payload stored in metadata."""

        @property
        def rfc_violations(self) -> t.MutableSequenceOf[str]:
            """RFC violations."""
            ...

        @property
        def errors(self) -> t.MutableSequenceOf[str]:
            """The validation errors."""
            ...

        @property
        def warnings(self) -> t.MutableSequenceOf[str]:
            """The validation warnings."""
            ...

        @property
        def context(self) -> t.MutableStrMapping:
            """The validation context."""
            ...

    @runtime_checkable
    class WriteOptions(Protocol):
        """Round-trip write options stored inside metadata."""

        @property
        def base_dn(self) -> str | None:
            """The base DN override."""
            ...

    @runtime_checkable
    class WriteFormatOptions(p.Model, Protocol):
        """Formatting options for entry serialization."""

        @property
        def line_width(self) -> int:
            """The line width for folding."""
            ...

        @property
        def sort_attributes(self) -> bool:
            """Whether attributes should be sorted."""
            ...

        @property
        def base64_encode_binary(self) -> bool:
            """Whether binary values should be base64 encoded."""
            ...

        @property
        def include_dn_comments(self) -> bool:
            """Whether DN comments should be emitted."""
            ...

        @property
        def include_version_header(self) -> bool:
            """Whether the LDIF version header should be emitted."""
            ...

        @property
        def include_timestamps(self) -> bool:
            """Whether generation timestamps should be emitted."""
            ...

        @property
        def restore_original_format(self) -> bool:
            """Whether original formatting should be restored."""
            ...

        @property
        def entry_category(self) -> str | None:
            """The migration entry category."""
            ...

    @runtime_checkable
    class FormatDetails(Protocol):
        """Original LDIF formatting details."""

        @property
        def dn_line(self) -> str | None:
            """The original DN line representation."""
            ...

    @runtime_checkable
    class SchemaFormatDetails(Protocol):
        """Original schema formatting details for round-trip preservation."""

        @property
        def original_string_complete(self) -> str | None:
            """The original schema definition."""
            ...

        @property
        def field_order(self) -> t.MutableSequenceOf[str]:
            """The original field order."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """The schema extensions metadata."""
            ...

    @runtime_checkable
    class MetadataWithWriteOptions(Protocol):
        """Metadata payload that may carry embedded write options."""

        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """The embedded write options."""
            ...

    @runtime_checkable
    class EntryStatistics(Protocol):
        """Entry-level processing and validation statistics."""

        was_parsed: bool
        was_validated: bool
        was_filtered: bool
        was_written: bool
        was_rejected: bool
        rejection_category: str | None
        rejection_reason: str | None
        attributes_added: t.MutableSequenceOf[str]
        attributes_removed: t.MutableSequenceOf[str]
        attributes_modified: t.MutableSequenceOf[str]
        attributes_filtered: t.MutableSequenceOf[str]
        servers_applied: t.MutableSequenceOf[str]
        dn_statistics: FlextLdifProtocolsBase.DNStatistics | None
        errors: t.MutableSequenceOf[str]
        warnings: t.MutableSequenceOf[str]

    @runtime_checkable
    class ServerMetadata(Protocol):
        """Server-specific metadata persisted on entries, ACLs, and schema items."""

        @property
        def server_type(self) -> str:
            """The server/server type identifier."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-write attribute — extensions is a
        # mutable JSON mapping the OID/relaxed handlers reassign in place
        # (metadata.extensions = {}); concrete field type equals this exactly so the
        # invariant read-write contract is satisfiable.
        extensions: t.MutableJsonMapping

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property (covariant) so the
        # concrete m.Ldif.ServerMetadata field (a subtype-carrying model) satisfies the
        # contract; a read-write attribute would be invariant and unsatisfiable. New
        # values flow through model_copy(update=...), the Pydantic-2 transition canon.
        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """The round-trip write options persisted in metadata."""
            ...

        @property
        def attribute_transformations(
            self,
        ) -> Mapping[str, FlextLdifProtocolsBase.AttributeTransformation]:
            """The per-attribute transformation audit trail (read-only view)."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): model_dump makes this protocol
        # structurally a flext-core p.Model so it is assignable into the
        # canonical model_copy update union (t.JsonPayload | p.Model).
        def model_dump(
            self,
            *,
            mode: str = "python",
            by_alias: bool | None = None,
            exclude_defaults: bool = False,
            exclude_none: bool = False,
        ) -> t.JsonDict:
            """Dump the validated model at an external serialization boundary."""
            ...

        @property
        def schema_format_details(
            self,
        ) -> FlextLdifProtocolsBase.SchemaFormatDetails | None:
            """The schema round-trip formatting details."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property the OUD round-trip
        # restore helper reads to recover original attribute-name casing; concrete
        # m.Ldif.ServerMetadata carries this field (domain_metadata.py:315).
        @property
        def original_attribute_case(self) -> t.MutableJsonMapping:
            """Original attribute-name casing for reverse conversion."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): frozen-transition canon for the
        # metadata-merge helpers (entry.metadata.model_copy(update={"extensions"})).
        def model_copy(
            self,
            *,
            update: t.MappingKV[str, t.JsonPayload | p.Model | t.SequenceOf[p.Model]]
            | None = None,
            deep: bool = False,
        ) -> Self:
            """Return an immutable copy with the given field updates."""
            ...

    @runtime_checkable
    class SchemaElement(Protocol):
        """Shared schema-element contract (attributes, objectClasses, syntaxes).

        NOTE (multi-agent, mro-0ftd.3.7.2): mirrors the concrete mb.SchemaElement
        base (domain_schema/_models/base.py) so SchemaModelT can bind to the
        protocol instead of the concrete model.
        """

        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific schema metadata."""
            ...

        @property
        def has_metadata(self) -> bool:
            """Whether the element carries server metadata."""
            ...

        @property
        def has_server_extensions(self) -> bool:
            """Whether the element carries server-specific extensions."""
            ...

        @property
        def server_type(self) -> str:
            """The server type from metadata, default RFC."""
            ...

        def model_copy(
            self,
            *,
            update: t.MappingKV[str, t.JsonPayload | p.Model | t.SequenceOf[p.Model]]
            | None = None,
            deep: bool = False,
        ) -> Self:
            """Return an immutable copy with the given field updates."""
            ...

    class SchemaAttribute(SchemaElement, Protocol):
        """LDIF schema attribute contract."""

        @property
        def oid(self) -> str:
            """The attribute OID."""
            ...

        @property
        def name(self) -> str:
            """The attribute name."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata/model_copy now inherited
        # from the SchemaElement base protocol (DRY).

    @runtime_checkable
    class SchemaObjectClass(SchemaElement, Protocol):
        """LDIF schema objectClass contract."""

        @property
        def oid(self) -> str:
            """The objectClass OID."""
            ...

        @property
        def name(self) -> str:
            """The objectClass name."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): schema business fields the fix_*
        # normalization helpers read — concrete model domain_schema.py:250/256.
        @property
        def sup(self) -> str | t.MutableSequenceOf[str] | None:
            """The superior object class(es) (RFC 4512 SUP)."""
            ...

        @property
        def kind(self) -> str:
            """The objectClass kind (STRUCTURAL/AUXILIARY/ABSTRACT)."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata/model_copy inherited from
        # the SchemaElement base protocol (DRY); sup/kind stay leaf-specific.

    @runtime_checkable
    class Acl(Protocol):
        """ACL model contract."""

        @property
        def name(self) -> str:
            """ACL name."""
            ...

        @property
        def server_type(self) -> str:
            """ACL server type."""
            ...

        @property
        def permissions(self) -> FlextLdifProtocolsBase.AclPermissions | None:
            """ACL permissions."""
            ...

        @property
        def raw_acl(self) -> str:
            """The original ACL string."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): complete the behavioral contract
        # (§3.2) — concrete model has metadata (domain_acl.py:175) and
        # model_copy via BaseModel; Pydantic-2-way frozen-transition canon.
        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific ACL metadata."""
            ...

        def model_copy(
            self,
            *,
            update: t.MappingKV[str, t.JsonPayload | p.Model | t.SequenceOf[p.Model]]
            | None = None,
            deep: bool = False,
        ) -> Self:
            """Return an immutable copy with the given field updates."""
            ...

    @runtime_checkable
    class Entry(Protocol):
        """Entry model contract used across LDIF services."""

        @property
        def dn(self) -> FlextLdifProtocolsBase.DN | None:
            """The entry DN."""
            ...

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """The entry attributes."""
            ...

        @property
        def changetype(self) -> c.Ldif.LdifChangeType | None:
            """The changetype when present."""
            ...

        @property
        def record_kind(self) -> c.Ldif.RecordKind:
            """Whether the record is content or change."""
            ...

        @property
        def newrdn(self) -> str | None:
            """The newrdn for moddn/modrdn records."""
            ...

        @property
        def deleteoldrdn(self) -> bool | None:
            """The deleteoldrdn for moddn/modrdn records."""
            ...

        @property
        def newsuperior(self) -> str | None:
            """The newsuperior for moddn records."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): complete the behavioral contract so
        # consumers can annotate payloads as p.Ldif.Entry (§3.2) instead of the
        # concrete m.Ldif.Entry. metadata is a read-only @property (covariant): the
        # concrete m.Ldif.Entry field satisfies it, while a read-write attribute would
        # be invariant and unsatisfiable. Handlers transition via
        # entry.model_copy(update={"metadata": ...}) — the Pydantic-2 frozen-transition
        # canon (works on the mutable DynamicModel too, mirroring SchemaElement/Acl).
        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific entry metadata."""
            ...

        def model_copy(
            self,
            *,
            update: t.MappingKV[str, t.JsonPayload | p.Model | t.SequenceOf[p.Model]]
            | None = None,
            deep: bool = False,
        ) -> Self:
            """Return an immutable copy with the given field updates."""
            ...

    @runtime_checkable
    class EntryValidationSubject(Protocol):
        """Minimal entry contract used by RFC/server validation helpers."""

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """The entry attributes for validation helpers."""
            ...

        @property
        def changetype(self) -> c.Ldif.LdifChangeType | None:
            """The entry changetype for validation helpers."""
            ...

    @runtime_checkable
    class EntryWithMetadata(Protocol):
        """Entry-like value that exposes write-capable metadata."""

        @property
        def metadata(self) -> FlextLdifProtocolsBase.MetadataWithWriteOptions | None:
            """The metadata that may carry write options."""
            ...

    @runtime_checkable
    class Statistics(Protocol):
        """Aggregate statistics payload for parse/write/migration flows."""

        @property
        def total_entries(self) -> int:
            """The total processed entries."""
            ...

        @property
        def processed_entries(self) -> int:
            """The successfully processed entries."""
            ...

        @property
        def failed_entries(self) -> int:
            """The failed entry count."""
            ...

        @property
        def rejected_entries(self) -> int:
            """The rejected entry count."""
            ...

        @property
        def events(
            self,
        ) -> t.SequenceOf[
            FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
        ]:
            """The accumulated processing events."""
            ...

    @runtime_checkable
    class Response(Protocol):
        """Canonical LDIF service response payload."""

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics:
            """The pipeline statistics."""
            ...

    @runtime_checkable
    class ParseResponse(Response, Protocol):
        """Parsed LDIF batch response."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """The parsed entries."""
            ...

        @property
        def detected_server_type(self) -> str | None:
            """The detected server type."""
            ...

    @runtime_checkable
    class ValidationResult(Protocol):
        """Validation summary contract."""

        @property
        def valid(self) -> bool:
            """The validation outcome."""
            ...

        @property
        def total_entries(self) -> int:
            """The validated entry count."""
            ...

        @property
        def valid_entries(self) -> int:
            """The valid entry count."""
            ...

        @property
        def invalid_entries(self) -> int:
            """The invalid entry count."""
            ...

        @property
        def errors(self) -> t.StrSequence:
            """The validation errors."""
            ...

    @runtime_checkable
    class MigrationPipelineResult(Protocol):
        """Migration pipeline result contract."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """The migrated entries."""
            ...

        @property
        def stats(self) -> FlextLdifProtocolsBase.Statistics:
            """The migration statistics."""
            ...

        @property
        def output_files(self) -> t.StrSequence:
            """The generated output files."""
            ...

    @runtime_checkable
    class AclResponse(Response, Protocol):
        """ACL extraction response payload."""

        @property
        def acls(self) -> t.SequenceOf[FlextLdifProtocolsBase.Acl]:
            """The extracted ACLs."""
            ...

    @runtime_checkable
    class WriteResponse(Response, Protocol):
        """Write response payload."""

        @property
        def content(self) -> str | None:
            """The serialized LDIF text."""
            ...

        @property
        def output_path(self) -> str | None:
            """The persisted output path."""
            ...

    @runtime_checkable
    class ConversionEvent(Protocol):
        """Conversion event contract."""

        @property
        def conversion_operation(self) -> str:
            """The conversion operation name."""
            ...

        @property
        def source_format(self) -> str:
            """The source format."""
            ...

        @property
        def target_format(self) -> str:
            """The target format."""
            ...

        @property
        def items_converted(self) -> int:
            """The converted item count."""
            ...

        @property
        def items_failed(self) -> int:
            """The failed item count."""
            ...

        @property
        def error_details(self) -> t.StrSequence | None:
            """The conversion error details."""
            ...

    @runtime_checkable
    class DnEvent(Protocol):
        """DN event contract."""

        @property
        def dn_operation(self) -> str:
            """DN operation name."""
            ...

        @property
        def input_dn(self) -> str:
            """The input DN."""
            ...

        @property
        def output_dn(self) -> str | None:
            """The output DN."""
            ...

        validation_result: bool | None

    @runtime_checkable
    class DnRegistry(Protocol):
        """DN registry contract used during conversions."""

        def clear(self) -> None:
            """Reset all registered DN state."""
            ...

        def resolve_canonical_dn(self, dn: str) -> str | None:
            """Return canonical DN casing when known."""
            ...

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register and return canonical DN casing."""
            ...

    @runtime_checkable
    class ModelWithValidationMetadata(Protocol):
        """Model exposing validation metadata for helper updates."""

        @property
        def validation_metadata(self) -> p.Model | None:
            """The validated metadata model when one is present."""
            ...

    @runtime_checkable
    class CategorizationService(Protocol):
        """Protocol for LDIF entry categorization services."""

        def categorize_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry],
        ) -> p.Result[FlextLdifProtocolsBase.FlexibleCategories]: ...

        def filter_by_base_dn(
            self,
            categories: FlextLdifProtocolsBase.FlexibleCategories,
        ) -> FlextLdifProtocolsBase.FlexibleCategories: ...

        def validate_dns(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]: ...

        def filter_schema_by_oids(
            self,
            schema_entries: Sequence[FlextLdifProtocolsBase.Entry],
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]: ...

    @runtime_checkable
    class ProcessingPipeline(Protocol):
        """Protocol for LDIF processing pipelines."""

        def execute(self) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]: ...

    @runtime_checkable
    class MigrationPipeline(Protocol):
        """Protocol for LDIF migration pipelines."""

        def execute(
            self,
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]: ...

    @runtime_checkable
    class ServerReference(Protocol):
        """Anything that can identify itself as a server via ``server_type``."""

        server_type: ClassVar[str]

    @runtime_checkable
    class ServerConstants(Protocol):
        """Server constants contract extracted from server namespaces."""

        SERVER_TYPE: str
        PRIORITY: int
        DETECTION_PATTERN: str | t.RegexPattern | None
        DETECTION_WEIGHT: int
        DETECTION_ATTRIBUTES: t.IterableOf[str]
        DETECTION_OID_PATTERN: str | t.RegexPattern | None
        DETECTION_ATTRIBUTE_PREFIXES: t.IterableOf[str] | None
        DETECTION_OBJECTCLASS_NAMES: t.IterableOf[str] | None
        DETECTION_DN_MARKERS: t.IterableOf[str] | None
        ACL_ATTRIBUTE_NAME: str | None
        CATEGORIZATION_PRIORITY: t.StrSequence
        CATEGORY_OBJECTCLASSES: t.FrozensetMapping
        HIERARCHY_PRIORITY_OBJECTCLASSES: frozenset[str]
        CATEGORIZATION_ACL_ATTRIBUTES: frozenset[str]

    @runtime_checkable
    class Predicate[T](Protocol):
        """Predicate function contract."""

        def __call__(self, item: T) -> bool:
            """Return whether the item matches the predicate."""
            ...


__all__: list[str] = ["FlextLdifProtocolsBase"]
