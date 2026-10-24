"""Base LDIF structural contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import ItemsView, KeysView, ValuesView
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif import c, m, p, t


class FlextLdifProtocolsBase:
    """Organize structural contracts without declaring an instance protocol."""

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
        """Server detection result contract."""

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes:
            """LDAP server type detected from LDIF content."""
            ...

        @property
        def confidence(self) -> t.DecimalFraction:
            """Detection confidence score between 0 and 1."""
            ...

        @property
        def scores(self) -> t.MutableMapping[str, int]:
            """Per-server-type detection scores."""
            ...

        @property
        def patterns_found(self) -> t.MutableSequenceOf[str]:
            """Server-identifying patterns found in LDIF."""
            ...

        @property
        def detection_error(self) -> str | None:
            """Error message if detection failed."""
            ...

        @property
        def fallback_reason(self) -> str | None:
            """Reason for using fallback server type."""
            ...

    @runtime_checkable
    class Entry(Protocol):
        """LDIF entry protocol."""

        @property
        def dn_str(self) -> str: ...

        @property
        def attributes_dict(self) -> t.MutableStrSequenceMapping: ...

        @property
        def changetype(self) -> c.Ldif.ChangeType | None: ...

        @property
        def change_operations(
            self,
        ) -> t.SequenceOf[FlextLdifProtocolsBase.ChangeOperation]: ...

    @runtime_checkable
    class ChangeOperation(Protocol):
        """LDIF change operation protocol."""

        @property
        def operation(self) -> c.Ldif.ChangeOperation: ...

        @property
        def attribute(self) -> str: ...

        @property
        def values(
            self,
        ) -> t.SequenceOf[FlextLdifProtocolsBase.ChangeOperationValue]: ...

    @runtime_checkable
    class ChangeOperationValue(Protocol):
        """LDIF change operation value protocol."""

        @property
        def value(self) -> str: ...

        @property
        def value_origin(self) -> c.Ldif.ValueOrigin: ...

        @property
        def raw_value(self) -> str | None: ...

    @runtime_checkable
    class Control(Protocol):
        """LDIF control protocol."""

        @property
        def control_type(self) -> str: ...

        @property
        def criticality(self) -> bool | None: ...

        @property
        def control_value(self) -> str | None: ...

        @property
        def control_value_origin(self) -> c.Ldif.ValueOrigin | None: ...

        @property
        def raw_value(self) -> str | None: ...

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
    class ServerServer(Protocol):
        """Structured server contract used by services and tests."""

        server_type: ClassVar[str]
        priority: ClassVar[int]
        Constants: ClassVar[type[FlextLdifProtocolsBase.ServerConstants]]

        @property
        def schema_server(self) -> FlextLdifProtocolsBase.SchemaServer: ...

        @property
        def acl_server(self) -> FlextLdifProtocolsBase.AclServer: ...

        @property
        def entry_server(self) -> FlextLdifProtocolsBase.EntryServer: ...

        def parse_ldif(self, value: str) -> p.Result[p.Ldif.ParseResponse]: ...

        def write(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]: ...

    @runtime_checkable
    class SchemaServer(Protocol):
        """Public schema parsing and serialization contract."""

        def parse_server(
            self, value: str
        ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]: ...

        def parse_input(
            self, schema_text: str
        ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]: ...

        def parse_attribute(
            self, definition: str
        ) -> p.Result[m.Ldif.SchemaAttribute]: ...

        def parse_objectclass(
            self, definition: str
        ) -> p.Result[m.Ldif.SchemaObjectClass]: ...

        def can_handle_attribute(self, attr_definition: str) -> bool: ...

        def can_handle_objectclass(self, oc_definition: str) -> bool: ...

        def write(
            self,
            model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        ) -> p.Result[str]: ...

        def write_attribute(
            self, attr_data: m.Ldif.SchemaAttribute
        ) -> p.Result[str]: ...

        def write_objectclass(
            self, oc_data: m.Ldif.SchemaObjectClass
        ) -> p.Result[str]: ...

    @runtime_checkable
    class AclServer(Protocol):
        """ACL parsing, serialization, and attribute discovery contract."""

        def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]: ...

        def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]: ...

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool: ...

        def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]: ...

    @runtime_checkable
    class EntryServer(Protocol):
        """Entry parsing and serialization capability, not a dialect registry."""

        def parse_server(
            self, value: str
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

        def parse_input(
            self, ldif_text: str
        ) -> t.MutableSequenceOf[m.Ldif.Entry] | None: ...

        def can_handle(
            self, entry_dn: str, attributes: t.MutableStrSequenceMapping
        ) -> bool: ...

        def parse_entry(
            self, entry_dn: str, entry_attrs: t.MutableStrSequenceMapping
        ) -> p.Result[m.Ldif.Entry]: ...

        def write(
            self,
            entry_data: m.Ldif.Entry | t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]: ...

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
        ) -> p.Result[FlextLdifProtocolsBase.ServerServer]: ...

        def resolve_base_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.ServerServer]: ...

        def schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]: ...

        def resolve_schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]: ...

        def acl(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.AclServer]: ...

        def entry(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.EntryServer]: ...

        def resolve_server_bundle(
            self, server_type: str
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsBase.SchemaServer
                | FlextLdifProtocolsBase.AclServer
                | FlextLdifProtocolsBase.EntryServer,
            ]
        ]: ...

        def resolve_server_constants(
            self, server_type: str
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]: ...

        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]: ...

        def summarize_registry(
            self,
        ) -> p.Result[t.Ldif.MutableMetadataInputMapping]: ...

        def register_server(
            self, server: FlextLdifProtocolsBase.ServerServer
        ) -> p.Result[bool]: ...

        def unregister_server(self, server_type: str) -> p.Result[bool]: ...

    @runtime_checkable
    class ServerReference(Protocol):
        """Anything that can identify itself as a server via ``server_type``."""

        server_type: str

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

        def update_count(self, key: str, value: int) -> None: ...

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
    class ParseResponse(Response, Protocol):
        """Parsed LDIF batch response."""

        @property
        def entries(self) -> t.SequenceOf[m.Ldif.Entry]: ...

        @property
        def detected_server_type(self) -> str | None: ...

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
        """Output naming capability consumed by migration composition."""

        @property
        def output_filename(self) -> str | None: ...

    @runtime_checkable
    class MigrationPipelineResult(Protocol):
        """Migration pipeline result contract."""

        @property
        def entries(self) -> t.SequenceOf[m.Ldif.Entry]: ...

        @property
        def stats(self) -> FlextLdifProtocolsBase.Statistics: ...

        @property
        def output_files(self) -> t.StrSequence: ...

    @runtime_checkable
    class FlexibleCategories(Protocol):
        """Flexible entry categorization result."""

        categorized: t.MappingKV[str, t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]]
        uncategorized: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]

    @runtime_checkable
    class ProcessEntriesOptions(Protocol):
        """Options for entry processing pipeline."""

        filter_invalid: bool
        apply_server_rules: bool
        validate_attributes: bool
        collect_statistics: bool

    @runtime_checkable
    class ProcessingResult(Protocol):
        """Result of processing a single entry."""

        entry: FlextLdifProtocolsBase.Entry
        success: bool
        error: str | None

    @runtime_checkable
    class EntriesStatistics(Protocol):
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

        def keys(self) -> t.KeysView[str]: ...

        def values(self) -> t.ValuesView[t.JsonValue]: ...

        def items(self) -> t.ItemsView[str, t.JsonValue]: ...

    @runtime_checkable
    class ConvertedModel(Protocol):
        """Converted LDIF model contract."""

        model_type: str
        converted_data: t.JsonValue

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

        def acl(self, server_type: str) -> p.Result[FlextLdifProtocolsBase.AclServer]:
            """Resolve ACL server by server type via the facade DSL."""
            ...

        def entry(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.EntryServer]:
            """Resolve entry server by server type via the facade DSL."""
            ...

        def resolve_base_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.ServerServer]:
            """Resolve base server by server type via the facade DSL."""
            ...

        def schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_schema_server(
            self, server_type: str
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]:
            """Resolve schema server by server type via the facade DSL."""
            ...

        def resolve_server_bundle(
            self,
            server_type: str,
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsBase.SchemaServer
                | FlextLdifProtocolsBase.AclServer
                | FlextLdifProtocolsBase.EntryServer,
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
            source: str
            | FlextLdifProtocolsBase.ServerReference
            | FlextLdifProtocolsBase.ServerServer,
            target: str
            | FlextLdifProtocolsBase.ServerReference
            | FlextLdifProtocolsBase.ServerServer,
            model_instance: FlextLdifProtocolsBase.Entry
            | FlextLdifProtocolsBase.SchemaAttribute
            | FlextLdifProtocolsBase.SchemaObjectClass
            | FlextLdifProtocolsBase.Acl,
        ) -> p.Result[FlextLdifProtocolsBase.ConvertedModel]:
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
    class LdifClient(
        ValidationService,
        ServerDetectionService,
        ServerResolutionService,
        Protocol,
    ):
        """Protocol for LDIF clients that support CRUD operations."""

        @property
        def settings(self) -> p.Ldif.Settings:
            """Expose the typed LDIF settings carried by the public facade."""
            ...

        def migrate(
            self,
            input_dir: Path | None = None,
            output_dir: Path | None = None,
            source_server: str = "rfc",
            target_server: str = "rfc",
            options: FlextLdifProtocolsBase.MigrationOutputOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Run the public LDIF migration pipeline."""
            ...

        def parse_ldif(
            self,
            value: str | Path,
            *,
            server_type: str | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ParseResponse]:
            """Parse LDIF content from text or file path."""
            ...

        def parse_ldif_file(
            self,
            path: Path,
            server_type: str | None = None,
            encoding: str = "utf-8",
        ) -> p.Result[FlextLdifProtocolsBase.ParseResponse]:
            """Parse LDIF content from a file path."""
            ...

        def parse_string(
            self,
            content: str,
            server_type: str | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ParseResponse]:
            """Parse LDIF content from a raw string."""
            ...

        def write(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.WriteResponse]:
            """Write canonical LDIF entries to text response."""
            ...

        def write_ldif_file(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            path: Path,
            *,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.WriteResponse]:
            """Write canonical LDIF entries to a file."""
            ...

        def write_to_string(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write LDIF entries to a string."""
            ...

        def validate_entries(
            self,
            entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            validation_service: FlextLdifProtocolsBase.ValidationService | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ValidationResult]:
            """Validate list of entries."""
            ...

        def service_check(self) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Run the public ACL service wiring check."""
            ...

        def parse_acl_string(
            self,
            acl_string: str,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.Acl]:
            """Parse one ACL string through the public facade DSL."""
            ...

        def extract_acls_from_entry(
            self,
            entry: FlextLdifProtocolsBase.Entry,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Extract ACLs from an entry through the public facade DSL."""
            ...

        def evaluate_acl_context(
            self,
            acls: t.SequenceOf[t.Ldif.AclLike],
            required_permissions: FlextLdifProtocolsBase.AclPermissions
            | t.MutableBoolMapping,
        ) -> p.Result[FlextLdifProtocolsBase.AclEvaluationResult]:
            """Evaluate ACLs through the public facade DSL."""
            ...

        def process_entries(
            self,
            entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry],
            options: FlextLdifProtocolsBase.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[t.MutableSequenceOf[FlextLdifProtocolsBase.ProcessingResult]]:
            """Process entries through the public facade DSL."""
            ...

        def calculate_for_entries(
            self,
            entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
        ) -> p.Result[FlextLdifProtocolsBase.EntriesStatistics]:
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
            """The DN string value."""
            ...

    @runtime_checkable
    class Attributes(Protocol):
        """Attribute container contract used by entry utilities."""

        @property
        def attributes(self) -> t.MutableMapping[str, t.MutableSequenceOf[str]]:
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
