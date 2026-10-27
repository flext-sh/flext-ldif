"""Base LDIF structural contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import ItemsView, KeysView, ValuesView
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import p, t

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif._protocols import FlextLdifProtocolsDomain, FlextLdifProtocolsValues
    from flext_ldif.models import FlextLdifModels
    from flext_ldif.typings import FlextLdifTypes


class FlextLdifProtocolsBase:
    """Organize structural contracts without declaring an instance protocol."""

    @runtime_checkable
    class LdifSettings(Protocol):
        """Namespaced LDIF runtime settings branch."""

        @property
        def ldif_encoding(self) -> str:
            """Default encoding for LDIF read/write operations."""
            ...

        @property
        def ldif_strict_validation(self) -> bool:
            """Whether strict LDIF validation is enabled."""
            ...

    @runtime_checkable
    class Settings(p.Cli.Settings, Protocol):
        """MRO-composed settings contract with the LDIF namespace.

        The ``Ldif`` branch mirrors the concrete ``FlextLdifSettings.Ldif``
        field: settings branches carry their config namespace's capitalized
        name (``settings.Ldif.*``), so the structural contract repeats it.
        """

        @property
        def Ldif(self) -> FlextLdifProtocolsBase.LdifSettings:
            """LDIF settings branch consumed without replacing its owner."""
            ...

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
        ) -> p.Result[FlextLdifProtocolsValues.ServerDetectionResult]:
            """Detect LDAP server type from LDIF file or content."""
            ...

    @runtime_checkable
    class Acl(Protocol):
        """ACL model contract."""

        @property
        def name(self) -> str: ...

        @property
        def server_type(self) -> str: ...

        @property
        def permissions(self) -> FlextLdifProtocolsBase.AclPermissions | None: ...

        @property
        def raw_acl(self) -> str: ...

    @runtime_checkable
    class AclTarget(Protocol):
        """ACL target descriptor."""

        @property
        def target_dn(self) -> str: ...

        @property
        def attributes(self) -> t.MutableSequenceOf[str]: ...

    @runtime_checkable
    class AclSubject(Protocol):
        """ACL subject descriptor."""

        @property
        def subject_type(self) -> str: ...

        @property
        def subject_value(self) -> str: ...

    @runtime_checkable
    class AclPermissions(Protocol):
        """ACL permission flag set."""

        @property
        def read(self) -> bool: ...

        @property
        def write(self) -> bool: ...

        @property
        def add(self) -> bool: ...

        @property
        def delete(self) -> bool: ...

        @property
        def search(self) -> bool: ...

        @property
        def compare(self) -> bool: ...

    @runtime_checkable
    class AclResponse(Protocol):
        """ACL extraction response payload."""

        @property
        def acls(self) -> t.SequenceOf[FlextLdifProtocolsBase.Acl]: ...

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics: ...

    @runtime_checkable
    class AclEvaluationResult(Protocol):
        """ACL evaluation result contract."""

        @property
        def granted(self) -> bool: ...

        @property
        def matched_acl(self) -> FlextLdifProtocolsBase.Acl | None: ...

        @property
        def message(self) -> str: ...

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics: ...

    @runtime_checkable
    class RegistryBound(Protocol):
        """Runtime registry dependency shared by LDIF services."""

        @property
        def registry(self) -> p.Registry: ...

    @runtime_checkable
    class ServerRegistry(RegistryBound, Protocol):
        """Dialect lookup and lifecycle contract implemented by the server service."""

        def server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]: ...

        def resolve_base_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]: ...

        def schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]: ...

        def resolve_schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]: ...

        def acl(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.AclServer]: ...

        def entry(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.EntryServer]: ...

        def resolve_server_bundle(
            self, server_type: str
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsDomain.SchemaServer
                | FlextLdifProtocolsDomain.AclServer
                | FlextLdifProtocolsDomain.EntryServer,
            ]
        ]: ...

        def resolve_server_constants(
            self, server_type: str
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]: ...

        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]: ...

        def summarize_registry(
            self,
        ) -> p.Result[t.MutableJsonMapping]: ...

        def register_server(
            self, server: FlextLdifProtocolsDomain.ServerServer
        ) -> p.Result[bool]: ...

        def unregister_server(self, server_type: str) -> p.Result[bool]: ...

    @runtime_checkable
    class ServerReference(Protocol):
        """Anything that can identify itself as a server via ``server_type``."""

        server_type: str

    @runtime_checkable
    class ServerConstants(Protocol):
        """Server constants contract extracted from server namespaces."""

        SERVER_TYPE: ClassVar[str]
        CANONICAL_NAME: ClassVar[str]
        ALIASES: ClassVar[frozenset[str]]
        PRIORITY: ClassVar[int]
        DETECTION_PATTERN: ClassVar[str]
        DETECTION_WEIGHT: ClassVar[int]
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]]
        DETECTION_OID_PATTERN: ClassVar[str]
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]]
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]]
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]]
        SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]]
        ACL_ATTRIBUTE_NAME: ClassVar[str]
        CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence]
        CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping]
        HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]]
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]]

    @runtime_checkable
    class SchemaAttribute(Protocol):
        """LDIF schema attribute contract."""

        @property
        def oid(self) -> str: ...

        @property
        def name(self) -> str: ...

    @runtime_checkable
    class SchemaObjectClass(Protocol):
        """LDIF schema objectClass contract."""

        @property
        def oid(self) -> str: ...

        @property
        def name(self) -> str: ...

        @property
        def sup(self) -> str | t.SequenceOf[str] | None: ...

        @property
        def must(self) -> t.SequenceOf[str] | None: ...

        @property
        def may(self) -> t.SequenceOf[str] | None: ...

    @runtime_checkable
    class SchemaItemKind(Protocol):
        """Schema item kind enumeration."""

        ATTRIBUTE: str
        OBJECTCLASS: str

    @runtime_checkable
    class DynamicCounts(Protocol):
        """Dynamic counter mapping for string->int statistics."""

        def __getitem__(self, key: str) -> int: ...

        def __len__(self) -> int: ...

        def __contains__(self, key: str) -> bool: ...

        def get(self, key: str, default: int | None = None) -> int | None: ...

        def keys(self) -> KeysView[str]: ...

        def values(self) -> ValuesView[int]: ...

        def items(self) -> ItemsView[str, int]: ...

    @runtime_checkable
    class Statistics(Protocol):
        """Aggregate statistics payload for parse/write/migration flows."""

        @property
        def total_entries(self) -> int: ...

        @property
        def processed_entries(self) -> int: ...

        @property
        def failed_entries(self) -> int: ...

        @property
        def rejected_entries(self) -> int: ...

        @property
        def events(
            self,
        ) -> t.SequenceOf[
            FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
        ]: ...

    @runtime_checkable
    class Response(Protocol):
        """Canonical LDIF service response payload."""

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics: ...

    @runtime_checkable
    class WriteResponse(Response, Protocol):
        """Serialized LDIF content and optional persisted output location."""

        @property
        def content(self) -> str | None: ...

        @property
        def output_path(self) -> str | None: ...

    @runtime_checkable
    class ValidationResult(Protocol):
        """Validation summary contract."""

        @property
        def valid(self) -> bool: ...

        @property
        def total_entries(self) -> int: ...

        @property
        def valid_entries(self) -> int: ...

        @property
        def invalid_entries(self) -> int: ...

        @property
        def errors(self) -> t.StrSequence: ...

    @runtime_checkable
    class MigrationOutputOptions(Protocol):
        """Output naming, ordering and formatting consumed by migration composition."""

        @property
        def output_filename(self) -> str | None: ...

        @property
        def sort_entries_hierarchically(self) -> bool: ...

        @property
        def format_options(self) -> FlextLdifModels.Ldif.WriteFormatOptions | None: ...

    @runtime_checkable
    class FlexibleCategories(Protocol):
        """Flexible entry categorization result."""

        categorized: t.MappingKV[
            str, t.MutableSequenceOf[FlextLdifProtocolsValues.Entry]
        ]
        uncategorized: t.MutableSequenceOf[FlextLdifProtocolsValues.Entry]

    @runtime_checkable
    class ProcessEntriesOptions(p.Model, Protocol):
        """Model-backed options validated by the entry processing pipeline."""

    @runtime_checkable
    class ProcessingResult(Protocol):
        """Result of processing a single entry."""

        @property
        def dn(self) -> str: ...

        @property
        def attributes(self) -> t.MutableStrSequenceMapping: ...

    @runtime_checkable
    class EntriesStatistics(p.Model, Protocol):
        """Aggregate entry processing statistics."""

        @property
        def total_entries(self) -> int: ...

        @property
        def object_class_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts: ...

        @property
        def server_type_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts: ...

    @runtime_checkable
    class ModelWithValidationMetadata(Protocol):
        """Model exposing validation metadata for helper updates."""

        validation_metadata: FlextLdifProtocolsBase.ConfigMap | None

    @runtime_checkable
    class ConfigMap(Protocol):
        """Configuration mapping contract."""

        def __getitem__(self, key: str) -> t.JsonValue: ...

        def __setitem__(self, key: str, value: t.JsonValue) -> None: ...

        def __contains__(self, key: str) -> bool: ...

        def get(self, key: str, default: t.JsonValue | None = None) -> t.JsonValue: ...

        def keys(self) -> KeysView[str]: ...

        def values(self) -> ValuesView[t.JsonValue]: ...

        def items(self) -> ItemsView[str, t.JsonValue]: ...

    @runtime_checkable
    class ConvertedModel(Protocol):
        """Converted LDIF model contract."""

        model_type: str
        converted_data: t.JsonValue

    @runtime_checkable
    class WriteFormatOptions(Protocol):
        """Formatting options for entry serialization."""

        @property
        def line_width(self) -> int: ...

        @property
        def sort_attributes(self) -> bool: ...

        @property
        def base64_encode_binary(self) -> bool: ...

        @property
        def include_dn_comments(self) -> bool: ...

        @property
        def restore_original_format(self) -> bool: ...

        @property
        def respect_attribute_order(self) -> bool: ...

        @property
        def write_hidden_attributes_as_comments(self) -> bool: ...

        @property
        def write_metadata_as_comments(self) -> bool: ...

        @property
        def include_version_header(self) -> bool: ...

        @property
        def entry_category(self) -> str | None: ...

    @runtime_checkable
    class ServerResolutionService(Protocol):
        """Contract for server registry resolution and model conversion."""

        def acl(self, server_type: str) -> p.Result[FlextLdifProtocolsDomain.AclServer]:
            """Resolve ACL server by server type via the facade DSL."""
            ...

        def entry(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.EntryServer]:
            """Resolve entry server by server type via the facade DSL."""
            ...

        def resolve_base_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]:
            """Resolve base server by server type via the facade DSL."""
            ...

        def schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_server_bundle(
            self,
            server_type: str,
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsDomain.SchemaServer
                | FlextLdifProtocolsDomain.AclServer
                | FlextLdifProtocolsDomain.EntryServer,
            ]
        ]:
            """Resolve schema/acl/entry bundle by server type via the facade DSL."""
            ...

        def resolve_server_constants(
            self,
            server_type: str,
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]:
            """Resolve the registered constants class without copying its namespace."""
            ...

        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
            """List registered server types via the facade DSL."""
            ...

        def summarize_registry(self) -> p.Result[t.MutableJsonMapping]:
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
            source: str
            | FlextLdifProtocolsBase.ServerReference
            | FlextLdifProtocolsDomain.ServerServer,
            target: str
            | FlextLdifProtocolsBase.ServerReference
            | FlextLdifProtocolsDomain.ServerServer,
            model_instance: FlextLdifProtocolsValues.Entry
            | FlextLdifProtocolsBase.SchemaAttribute
            | FlextLdifProtocolsBase.SchemaObjectClass
            | FlextLdifProtocolsBase.Acl,
        ) -> p.Result[FlextLdifTypes.Ldif.ConvertedModel]:
            """Convert one LDIF model between server servers."""
            ...

        def resolve_effective_server_type(
            self,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
        ) -> p.Result[str]:
            """Resolve the effective LDAP server type for public processing flows."""
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
            """The DN string value."""
            ...

    @runtime_checkable
    class Attributes(Protocol):
        """Attribute container contract used by entry utilities."""

        @property
        def attributes(self) -> t.MutableStrSequenceMapping:
            """The underlying attribute mapping."""
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
    class WriteOptions(Protocol):
        """Round-trip write options stored inside metadata."""

        @property
        def base_dn(self) -> str | None:
            """The base DN override."""
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
    class Predicate[T](Protocol):
        """Predicate function contract."""

        def __call__(self, item: T) -> bool:
            """Return whether the item matches the predicate."""
            ...


__all__: list[str] = ["FlextLdifProtocolsBase"]
