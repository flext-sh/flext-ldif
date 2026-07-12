"""Base LDIF structural contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import (
        KeysView,
        MutableMapping,
        ValuesView,
    )
    from pathlib import Path

    from flext_ldif import (
        FlextLdifProtocols as lp,
        c,
        m,
        p,
        t,
    )
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain as lpd


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
        ) -> p.Result[m.Ldif.ServerDetectionResult]:
            """Detect LDAP server type from LDIF file or content."""
            ...

    @runtime_checkable
    class LdifClient(ValidationService, ServerDetectionService, Protocol):
        """Protocol for LDIF clients that support CRUD operations."""

        @property
        def settings(self) -> lp.Ldif.Settings:
            """Expose the typed LDIF settings carried by the public facade."""
            ...

        def migrate(
            self,
            input_dir: Path | None = None,
            output_dir: Path | None = None,
            source_server: str = "rfc",
            target_server: str = "rfc",
            options: m.Ldif.MigrateOptions | None = None,
        ) -> p.Result[m.Ldif.MigrationPipelineResult]:
            """Run the public LDIF migration pipeline."""
            ...

        def parse_ldif(
            self,
            value: str | Path,
            *,
            server_type: str | None = None,
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from text or file path."""
            ...

        def parse_ldif_file(
            self,
            path: Path,
            server_type: str | None = None,
            encoding: str = "utf-8",
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from a file path."""
            ...

        def parse_string(
            self,
            content: str,
            server_type: str | None = None,
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from a raw string."""
            ...

        def write(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to text response."""
            ...

        def write_ldif_file(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            path: Path,
            *,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a file."""
            ...

        def write_to_string(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            server_type: str | None = None,
        ) -> p.Result[str]:
            """Write LDIF entries to a string."""
            ...

        def acl(self, server_type: str) -> p.Result[lpd.AclServer]:
            """Resolve ACL server by server type via the facade DSL."""
            ...

        def entry(self, server_type: str) -> p.Result[lpd.EntryServer]:
            """Resolve entry server by server type via the facade DSL."""
            ...

        def resolve_base_server(
            self,
            server_type: str,
        ) -> p.Result[lpd.ServerServer]:
            """Resolve base server by server type via the facade DSL."""
            ...

        def schema_server(self, server_type: str) -> p.Result[lpd.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_schema_server(
            self,
            server_type: str,
        ) -> p.Result[lpd.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_server_bundle(
            self,
            server_type: str,
        ) -> p.Result[
            t.MappingKV[
                str,
                lpd.SchemaServer | lpd.AclServer | lpd.EntryServer,
            ]
        ]:
            """Resolve schema/acl/entry bundle by server type via the facade DSL."""
            ...

        def resolve_server_constants(
            self,
            server_type: str,
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]:
            """Resolve server constants by server type via the facade DSL."""
            ...

        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
            """List registered server types via the facade DSL."""
            ...

        def summarize_registry(self) -> p.Result[t.Ldif.MutableMetadataInputMapping]:
            """Return registry summary metadata via the facade DSL."""
            ...

        def resolve_supported_conversions(
            self,
            server: FlextLdifProtocolsBase.ServerReference | str,
        ) -> t.MappingKV[str, bool]:
            """Return supported conversion categories for a server server."""
            ...

        def convert_model(
            self,
            source: str | FlextLdifProtocolsBase.ServerReference | lpd.ServerServer,
            target: str | FlextLdifProtocolsBase.ServerReference | lpd.ServerServer,
            model_instance: m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl,
        ) -> p.Result[t.Ldif.ConvertedModel]:
            """Convert one LDIF model between server servers."""
            ...

        def resolve_effective_server_type(
            self,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
        ) -> p.Result[str]:
            """Resolve the effective LDAP server type for public processing flows."""
            ...

        def validate_entries(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            validation_service: FlextLdifProtocolsBase.ValidationService | None = None,
        ) -> p.Result[m.Ldif.ValidationResult]:
            """Validate list of entries."""
            ...

        def service_check(self) -> p.Result[m.Ldif.AclResponse]:
            """Run the public ACL service wiring check."""
            ...

        def parse_acl_string(
            self,
            acl_string: str,
            server_type: str,
        ) -> p.Result[m.Ldif.Acl]:
            """Parse one ACL string through the public facade DSL."""
            ...

        def extract_acls_from_entry(
            self,
            entry: m.Ldif.Entry,
            server_type: str,
        ) -> p.Result[m.Ldif.AclResponse]:
            """Extract ACLs from an entry through the public facade DSL."""
            ...

        def evaluate_acl_context(
            self,
            acls: t.SequenceOf[t.Ldif.AclLike],
            required_permissions: m.Ldif.AclPermissions | t.MutableBoolMapping,
        ) -> p.Result[m.Ldif.AclEvaluationResult]:
            """Evaluate ACLs through the public facade DSL."""
            ...

        def process_entries(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
            options: m.Ldif.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.ProcessingResult]]:
            """Process entries through the public facade DSL."""
            ...

        def calculate_for_entries(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        ) -> p.Result[m.Ldif.EntriesStatistics]:
            """Calculate entry statistics through the public facade DSL."""
            ...

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
            """Return the DN string value."""
            ...

    @runtime_checkable
    class Attributes(Protocol):
        """Attribute container contract used by entry utilities."""

        @property
        def attributes(self) -> MutableMapping[str, t.MutableSequenceOf[str]]:
            """Return the underlying attribute mapping."""
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
    class Control(Protocol):
        """Structured LDIF control line."""

        control_type: str
        criticality: bool | None
        value: str | None
        value_origin: c.Ldif.ValueOrigin | None
        raw_value: str | None

    @runtime_checkable
    class ChangeOperationValue(Protocol):
        """Single decoded value in a modify block."""

        value: str
        value_origin: c.Ldif.ValueOrigin
        raw_value: str | None

    @runtime_checkable
    class ChangeOperation(Protocol):
        """Structured modify block."""

        operation: c.Ldif.ChangeOperation
        attribute: str
        values: t.SequenceOf[m.Ldif.ChangeOperationValue]

    @runtime_checkable
    class AclPermissions(Protocol):
        """ACL permission flag set."""

        @property
        def read(self) -> bool:
            """Return whether read is allowed."""
            ...

        @property
        def write(self) -> bool:
            """Return whether write is allowed."""
            ...

        @property
        def search(self) -> bool:
            """Return whether search is allowed."""
            ...

        @property
        def compare(self) -> bool:
            """Return whether compare is allowed."""
            ...

    @runtime_checkable
    class AclTarget(Protocol):
        """ACL target descriptor."""

        @property
        def target_dn(self) -> str:
            """Return target DN expression."""
            ...

        @property
        def attributes(self) -> t.MutableSequenceOf[str]:
            """Return target attribute names."""
            ...

    @runtime_checkable
    class AclSubject(Protocol):
        """ACL subject descriptor."""

        @property
        def subject_type(self) -> str:
            """Return subject type."""
            ...

        @property
        def subject_value(self) -> str:
            """Return subject value."""
            ...

    @runtime_checkable
    class ValidationMetadata(Protocol):
        """Validation result payload stored in metadata."""

        @property
        def rfc_violations(self) -> t.MutableSequenceOf[str]:
            """Return RFC violations."""
            ...

        @property
        def errors(self) -> t.MutableSequenceOf[str]:
            """Return validation errors."""
            ...

        @property
        def warnings(self) -> t.MutableSequenceOf[str]:
            """Return validation warnings."""
            ...

        @property
        def context(self) -> t.MutableStrMapping:
            """Return validation context."""
            ...

    @runtime_checkable
    class WriteOptions(Protocol):
        """Round-trip write options stored inside metadata."""

        @property
        def base_dn(self) -> str | None:
            """Return base DN override."""
            ...

    @runtime_checkable
    class WriteFormatOptions(Protocol):
        """Formatting options for entry serialization."""

        @property
        def line_width(self) -> int:
            """Return line width for folding."""
            ...

        @property
        def sort_attributes(self) -> bool:
            """Return whether attributes should be sorted."""
            ...

        @property
        def base64_encode_binary(self) -> bool:
            """Return whether binary values should be base64 encoded."""
            ...

        @property
        def include_dn_comments(self) -> bool:
            """Return whether DN comments should be emitted."""
            ...

        @property
        def restore_original_format(self) -> bool:
            """Return whether original formatting should be restored."""
            ...

        @property
        def entry_category(self) -> str | None:
            """Return migration entry category."""
            ...

    @runtime_checkable
    class FormatDetails(Protocol):
        """Original LDIF formatting details."""

        @property
        def dn_line(self) -> str | None:
            """Return original DN line representation."""
            ...

    @runtime_checkable
    class SchemaFormatDetails(Protocol):
        """Original schema formatting details for round-trip preservation."""

        @property
        def original_string_complete(self) -> str | None:
            """Return the original schema definition."""
            ...

        @property
        def field_order(self) -> t.MutableSequenceOf[str]:
            """Return original field order."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """Return schema extensions metadata."""
            ...

    @runtime_checkable
    class MetadataWithWriteOptions(Protocol):
        """Metadata payload that may carry embedded write options."""

        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """Return embedded write options."""
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
            """Return server/server type identifier."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """Return dynamic extensions."""
            ...

        @property
        def schema_format_details(
            self,
        ) -> FlextLdifProtocolsBase.SchemaFormatDetails | None:
            """Return schema round-trip formatting details."""
            ...

    @runtime_checkable
    class SchemaAttribute(Protocol):
        """LDIF schema attribute contract."""

        @property
        def oid(self) -> str:
            """Return attribute OID."""
            ...

        @property
        def name(self) -> str:
            """Return attribute name."""
            ...

    @runtime_checkable
    class SchemaObjectClass(Protocol):
        """LDIF schema objectClass contract."""

        @property
        def oid(self) -> str:
            """Return objectClass OID."""
            ...

        @property
        def name(self) -> str:
            """Return objectClass name."""
            ...

    @runtime_checkable
    class Acl(Protocol):
        """ACL model contract."""

        @property
        def name(self) -> str:
            """Return ACL name."""
            ...

        @property
        def server_type(self) -> str:
            """Return ACL server type."""
            ...

        @property
        def permissions(self) -> FlextLdifProtocolsBase.AclPermissions | None:
            """Return ACL permissions."""
            ...

        @property
        def raw_acl(self) -> str:
            """Return original ACL string."""
            ...

    @runtime_checkable
    class Entry(Protocol):
        """Entry model contract used across LDIF services."""

        change_operations: t.MutableSequenceOf[m.Ldif.ChangeOperation]

        @property
        def dn(self) -> FlextLdifProtocolsBase.DN | None:
            """Return entry DN."""
            ...

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """Return entry attributes."""
            ...

        @property
        def changetype(self) -> c.Ldif.LdifChangeType | None:
            """Return changetype when present."""
            ...

        @property
        def record_kind(self) -> c.Ldif.RecordKind:
            """Return whether the record is content or change."""
            ...

        @property
        def controls(self) -> t.SequenceOf[m.Ldif.Control]:
            """Return parsed LDIF controls."""
            ...

        @property
        def newrdn(self) -> str | None:
            """Return newrdn for moddn/modrdn records."""
            ...

        @property
        def deleteoldrdn(self) -> bool | None:
            """Return deleteoldrdn for moddn/modrdn records."""
            ...

        @property
        def newsuperior(self) -> str | None:
            """Return newsuperior for moddn records."""
            ...

    @runtime_checkable
    class EntryValidationSubject(Protocol):
        """Minimal entry contract used by RFC/server validation helpers."""

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """Return entry attributes for validation helpers."""
            ...

        @property
        def changetype(self) -> c.Ldif.LdifChangeType | None:
            """Return entry changetype for validation helpers."""
            ...

    @runtime_checkable
    class EntryWithMetadata(Protocol):
        """Entry-like value that exposes write-capable metadata."""

        @property
        def metadata(self) -> FlextLdifProtocolsBase.MetadataWithWriteOptions | None:
            """Return metadata that may carry write options."""
            ...

    @runtime_checkable
    class Statistics(Protocol):
        """Aggregate statistics payload for parse/write/migration flows."""

        @property
        def total_entries(self) -> int:
            """Return total processed entries."""
            ...

        @property
        def processed_entries(self) -> int:
            """Return successfully processed entries."""
            ...

        @property
        def failed_entries(self) -> int:
            """Return failed entry count."""
            ...

        @property
        def rejected_entries(self) -> int:
            """Return rejected entry count."""
            ...

        @property
        def events(
            self,
        ) -> t.SequenceOf[
            FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
        ]:
            """Return accumulated processing events."""
            ...

    @runtime_checkable
    class Response(Protocol):
        """Canonical LDIF service response payload."""

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics:
            """Return pipeline statistics."""
            ...

    @runtime_checkable
    class ParseResponse(Response, Protocol):
        """Parsed LDIF batch response."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """Return parsed entries."""
            ...

        @property
        def detected_server_type(self) -> str | None:
            """Return detected server type."""
            ...

    @runtime_checkable
    class ValidationResult(Protocol):
        """Validation summary contract."""

        @property
        def valid(self) -> bool:
            """Return validation outcome."""
            ...

        @property
        def total_entries(self) -> int:
            """Return validated entry count."""
            ...

        @property
        def valid_entries(self) -> int:
            """Return valid entry count."""
            ...

        @property
        def invalid_entries(self) -> int:
            """Return invalid entry count."""
            ...

        @property
        def errors(self) -> t.StrSequence:
            """Return validation errors."""
            ...

    @runtime_checkable
    class MigrationPipelineResult(Protocol):
        """Migration pipeline result contract."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """Return migrated entries."""
            ...

        @property
        def stats(self) -> FlextLdifProtocolsBase.Statistics:
            """Return migration statistics."""
            ...

        @property
        def output_files(self) -> t.StrSequence:
            """Return generated output files."""
            ...

    @runtime_checkable
    class AclResponse(Response, Protocol):
        """ACL extraction response payload."""

        @property
        def acls(self) -> t.SequenceOf[FlextLdifProtocolsBase.Acl]:
            """Return extracted ACLs."""
            ...

    @runtime_checkable
    class WriteResponse(Response, Protocol):
        """Write response payload."""

        @property
        def content(self) -> str | None:
            """Return serialized LDIF text."""
            ...

        @property
        def output_path(self) -> str | None:
            """Return persisted output path."""
            ...

    @runtime_checkable
    class ConversionEvent(Protocol):
        """Conversion event contract."""

        @property
        def conversion_operation(self) -> str:
            """Return conversion operation name."""
            ...

        @property
        def source_format(self) -> str:
            """Return source format."""
            ...

        @property
        def target_format(self) -> str:
            """Return target format."""
            ...

        @property
        def items_converted(self) -> int:
            """Return converted item count."""
            ...

        @property
        def items_failed(self) -> int:
            """Return failed item count."""
            ...

        @property
        def error_details(self) -> t.StrSequence | None:
            """Return conversion error details."""
            ...

    @runtime_checkable
    class DnEvent(Protocol):
        """DN event contract."""

        @property
        def dn_operation(self) -> str:
            """Return DN operation name."""
            ...

        @property
        def input_dn(self) -> str:
            """Return input DN."""
            ...

        @property
        def output_dn(self) -> str | None:
            """Return output DN."""
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

        validation_metadata: m.ConfigMap | None

    @runtime_checkable
    class CategorizationService(Protocol):
        """Protocol for LDIF entry categorization services."""

        def categorize_entries(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
        ) -> p.Result[m.Ldif.FlexibleCategories]: ...

        def filter_by_base_dn(
            self,
            categories: m.Ldif.FlexibleCategories,
        ) -> m.Ldif.FlexibleCategories: ...

        def validate_dns(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

        def filter_schema_by_oids(
            self,
            schema_entries: t.MutableSequenceOf[m.Ldif.Entry],
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

    @runtime_checkable
    class ProcessingPipeline(Protocol):
        """Protocol for LDIF processing pipelines."""

        def execute(self) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

    @runtime_checkable
    class MigrationPipeline(Protocol):
        """Protocol for LDIF migration pipelines."""

        def execute(self) -> p.Result[m.Ldif.MigrationPipelineResult]: ...

    @runtime_checkable
    class ServerReference(Protocol):
        """Anything that can identify itself as a server via ``server_type``."""

        server_type: ClassVar[str]

    @runtime_checkable
    class ServerConstants(Protocol):
        """Server constants contract extracted from server namespaces."""

        SERVER_TYPE: str
        PRIORITY: int
        DETECTION_PATTERN: str | t.Ldif.RegexPattern | None
        DETECTION_WEIGHT: int
        DETECTION_ATTRIBUTES: t.IterableOf[str]
        DETECTION_OID_PATTERN: str | t.Ldif.RegexPattern | None
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
