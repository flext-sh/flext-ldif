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

from flext_core import FlextTypes

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
        transformations: Sequence[str]
        validation_warnings: Sequence[str]
        validation_errors: Sequence[str]
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
        def context(self) -> FlextTypes.MutableStrMapping:
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

        total_entries: int
        processed_entries: int
        failed_entries: int
        rejected_entries: int
        events: MutableSequence[
            FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
        ]

    @runtime_checkable
    class ParseResponse(Protocol):
        """Parsed LDIF batch response."""

        entries: MutableSequence[FlextLdifProtocolsBase.Entry]
        statistics: FlextLdifProtocolsBase.Statistics
        detected_server_type: str | None

    @runtime_checkable
    class ValidationResult(Protocol):
        """Validation summary contract."""

        is_valid: bool
        total_entries: int
        valid_entries: int
        invalid_entries: int
        errors: MutableSequence[str]

    @runtime_checkable
    class MigrationPipelineResult(Protocol):
        """Migration pipeline result contract."""

        entries: MutableSequence[FlextLdifProtocolsBase.Entry]
        stats: FlextLdifProtocolsBase.Statistics
        output_files: MutableSequence[str]

    @runtime_checkable
    class WriteResponse(Protocol):
        """Write response payload."""

        content: str | None
        statistics: FlextLdifProtocolsBase.Statistics

    @runtime_checkable
    class ConversionEvent(Protocol):
        """Conversion event contract."""

        conversion_operation: str
        source_format: str
        target_format: str
        items_converted: int
        items_failed: int
        error_details: MutableSequence[str] | None

    @runtime_checkable
    class DnEvent(Protocol):
        """DN event contract."""

        dn_operation: str
        input_dn: str
        output_dn: str | None
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

        validation_metadata: FlextTypes.ConfigMap | None

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
        CATEGORY_OBJECTCLASSES: FlextTypes.MutableFrozensetMapping

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


__all__ = ["FlextLdifProtocolsBase"]
