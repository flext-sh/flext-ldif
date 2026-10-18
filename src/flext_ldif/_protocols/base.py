"""Base LDIF structural contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import ItemsView, KeysView, ValuesView
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

    from flext_cli import p

    from flext_ldif import c, t
    from flext_ldif._protocols import FlextLdifProtocolsDomain


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
            | FlextLdifProtocolsDomain.ServerServer,
            target: str
            | FlextLdifProtocolsBase.ServerReference
            | FlextLdifProtocolsDomain.ServerServer,
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
            """Migrate LDIF data between servers."""
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
    class MigrationOutputOptions(Protocol):
        """Migration output options contract."""

        output_filename: str | None

    @runtime_checkable
    class MigrationPipelineResult(Protocol):
        """Migration pipeline result contract."""

        @property
        def migrated_schema(self) -> FlextLdifProtocolsBase.SchemaContent: ...

        @property
        def entries(self) -> t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]: ...

    @runtime_checkable
    class ParseResponse(Protocol):
        """LDIF parse response contract."""

        @property
        def entries(self) -> t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]: ...

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics: ...

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes | None: ...

    @runtime_checkable
    class Statistics(Protocol):
        """Statistics contract."""

        @property
        def total_entries(self) -> int: ...

        @property
        def processed_entries(self) -> int: ...

    @runtime_checkable
    class SchemaContent(Protocol):
        """Schema content contract."""

        @property
        def attributes(
            self,
        ) -> t.MutableSequenceOf[FlextLdifProtocolsBase.SchemaAttribute]: ...

        @property
        def object_classes(
            self,
        ) -> t.MutableSequenceOf[FlextLdifProtocolsBase.SchemaObjectClass]: ...

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
    class FlexibleCategories(Protocol):
        """Flexible entry categorization result."""

        categorized: t.MappingKV[str, t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]]
        uncategorized: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]

    @runtime_checkable
    class CategorizationService(Protocol):
        """Protocol for LDIF entry categorization services."""

        def categorize_entries(
            self,
            entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry],
        ) -> p.Result[FlextLdifProtocolsBase.FlexibleCategories]: ...

        def filter_by_base_dn(
            self,
            categories: FlextLdifProtocolsBase.FlexibleCategories,
        ) -> FlextLdifProtocolsBase.FlexibleCategories: ...

        def validate_dns(
            self,
            entries: (
                t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]
                | FlextLdifProtocolsBase.ParseResponse
            ),
        ) -> p.Result[t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]]: ...

        def filter_schema_by_oids(
            self,
            schema_entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry],
        ) -> p.Result[t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]]: ...

    @runtime_checkable
    class ModelWithValidationMetadata(Protocol):
        """Model exposing validation metadata for helper updates."""

        validation_metadata: t.MutableJsonMapping | None

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
    class ServerReference(Protocol):
        """Minimal server reference contract."""

        server_type: str

    @runtime_checkable
    class ConvertedModel(Protocol):
        """Converted LDIF model contract."""

        model_type: str
        converted_data: t.JsonValue

    @runtime_checkable
    class WriteFormatOptions(Protocol):
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
        def restore_original_format(self) -> bool:
            """Whether original formatting should be restored."""
            ...

        @property
        def respect_attribute_order(self) -> bool:
            """Whether attribute order from metadata should be respected."""
            ...

        @property
        def write_hidden_attributes_as_comments(self) -> bool:
            """Whether hidden attributes should be written as comments."""
            ...

        @property
        def write_metadata_as_comments(self) -> bool:
            """Whether metadata should be written as comments."""
            ...

        @property
        def include_version_header(self) -> bool:
            """Whether version header should be included."""
            ...


__all__: list[str] = ["FlextLdifProtocolsBase"]
