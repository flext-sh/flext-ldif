"""Base LDIF structural contracts."""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
    ValuesView,
)
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import m

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsBase(Protocol):
    """Base LDIF protocols shared across utilities, services, and servers."""

    @runtime_checkable
    class DynamicMetadata(Protocol):
        """Mapping-like metadata contract for dynamic extensions."""

        def __getitem__(self, key: str) -> t.Ldif.MetadataValue:
            """Return metadata value by key."""
            ...

        def get(
            self,
            key: str,
            default: t.Ldif.MetadataValue | None = None,
        ) -> t.Ldif.MetadataValue | None:
            """Return metadata value by key with optional default."""
            ...

        def items(self) -> ItemsView[str, t.Ldif.MetadataValue]:
            """Return metadata items view."""
            ...

        def keys(self) -> KeysView[str]:
            """Return metadata keys view."""
            ...

        def values(self) -> ValuesView[t.Ldif.MetadataValue]:
            """Return metadata values view."""
            ...

        def to_dict(self) -> MutableMapping[str, t.Ldif.MetadataValue]:
            """Convert metadata to a mutable dictionary."""
            ...

        def model_dump(self) -> Mapping[str, t.Ldif.MetadataValue]:
            """Serialize metadata to a mapping."""
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
        def attributes(self) -> MutableMapping[str, MutableSequence[str]]:
            """Return the underlying attribute mapping."""
            ...

        def get(
            self,
            key: str,
            default: MutableSequence[str] | None = None,
        ) -> MutableSequence[str]:
            """Return attribute values with optional default."""
            ...

        def items(self) -> MutableSequence[tuple[str, MutableSequence[str]]]:
            """Return attribute items as a list of tuples."""
            ...

        def keys(self) -> KeysView[str]:
            """Return attribute names view."""
            ...

        def values(self) -> ValuesView[MutableSequence[str]]:
            """Return attribute value lists view."""
            ...

    @runtime_checkable
    class AttributeTransformation(Protocol):
        """Attribute transformation audit record."""

        original_name: str
        target_name: str | None
        original_values: MutableSequence[str]
        target_values: MutableSequence[str] | None
        transformation_type: str
        reason: str

    @runtime_checkable
    class Control(Protocol):
        """Structured LDIF control line."""

        control_type: str
        criticality: bool | None
        value: str | None
        value_origin: str | None
        raw_value: str | None

    @runtime_checkable
    class ChangeOperationValue(Protocol):
        """Single decoded value in a modify block."""

        value: str
        value_origin: str
        raw_value: str | None

    @runtime_checkable
    class ChangeOperation(Protocol):
        """Structured modify block."""

        operation: str
        attribute: str
        values: Sequence[FlextLdifProtocolsBase.ChangeOperationValue]

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
        def attributes(self) -> MutableSequence[str]:
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
        def rfc_violations(self) -> MutableSequence[str]:
            """Return RFC violations."""
            ...

        @property
        def errors(self) -> MutableSequence[str]:
            """Return validation errors."""
            ...

        @property
        def warnings(self) -> MutableSequence[str]:
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
        def field_order(self) -> MutableSequence[str]:
            """Return original field order."""
            ...

        @property
        def extensions(self) -> FlextLdifProtocolsBase.DynamicMetadata:
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
        attributes_added: MutableSequence[str]
        attributes_removed: MutableSequence[str]
        attributes_modified: MutableSequence[str]
        attributes_filtered: MutableSequence[str]
        quirks_applied: MutableSequence[str]
        dn_statistics: FlextLdifProtocolsBase.DNStatistics | None
        errors: MutableSequence[str]
        warnings: MutableSequence[str]

    @runtime_checkable
    class QuirkMetadata(Protocol):
        """Quirk-specific metadata persisted on entries, ACLs, and schema items."""

        @property
        def quirk_type(self) -> str:
            """Return quirk/server type identifier."""
            ...

        @property
        def extensions(self) -> FlextLdifProtocolsBase.DynamicMetadata:
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

        @property
        def dn(self) -> FlextLdifProtocolsBase.DN | None:
            """Return entry DN."""
            ...

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """Return entry attributes."""
            ...

        @property
        def changetype(self) -> str | None:
            """Return changetype when present."""
            ...

        @property
        def record_kind(self) -> str:
            """Return whether the record is content or change."""
            ...

        @property
        def controls(self) -> Sequence[object]:
            """Return parsed LDIF controls."""
            ...

        @property
        def change_operations(
            self,
        ) -> Sequence[object]:
            """Return parsed modify blocks."""
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
        ) -> Sequence[
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
        def entries(self) -> Sequence[FlextLdifProtocolsBase.Entry]:
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
        def entries(self) -> Sequence[FlextLdifProtocolsBase.Entry]:
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
        def acls(self) -> Sequence[FlextLdifProtocolsBase.Acl]:
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

        def get_canonical_dn(self, dn: str) -> str | None:
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
    class ServerConstants(Protocol):
        """Server constants contract extracted from server namespaces."""

        SERVER_TYPE: str
        PRIORITY: int
        DETECTION_OID_PATTERN: str | None
        DETECTION_ATTRIBUTE_PREFIXES: frozenset[str] | None
        DETECTION_OBJECTCLASS_NAMES: frozenset[str] | None
        DETECTION_DN_MARKERS: frozenset[str] | None
        ACL_ATTRIBUTE_NAME: str | None
        CATEGORIZATION_PRIORITY: MutableSequence[str]
        CATEGORY_OBJECTCLASSES: t.MutableFrozensetMapping

    @runtime_checkable
    class ServerDetectionConstants(Protocol):
        """Subset of constants used by detector services."""

        DETECTION_PATTERN: str
        DETECTION_WEIGHT: int
        DETECTION_ATTRIBUTES: frozenset[str] | MutableSequence[str]
        DETECTION_OID_PATTERN: str | None
        DETECTION_OBJECTCLASS_NAMES: frozenset[str] | MutableSequence[str] | None

    @runtime_checkable
    class Predicate[T](Protocol):
        """Predicate function contract."""

        def __call__(self, item: T) -> bool:
            """Return whether the item matches the predicate."""
            ...


__all__: list[str] = ["FlextLdifProtocolsBase"]
