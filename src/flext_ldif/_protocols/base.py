"""Base LDIF structural contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    Mapping,
    MutableSequence,
    Sequence,
    ValuesView,
)
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols, p, t

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif._protocols import (
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsDomainAcl,
        FlextLdifProtocolsDomainEntry,
        FlextLdifProtocolsDomainMetadata,
        FlextLdifProtocolsDomainSchema,
        FlextLdifProtocolsResults,
    )
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

        The ``Ldif`` attribute mirrors the concrete ``FlextLdifSettings.Ldif``
        field, so the structural contract repeats its name and shape.
        """

        Ldif: FlextLdifProtocolsBase.LdifSettings

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
        ) -> p.Result[FlextLdifProtocolsResults.ServerDetectionResult]:
            """Detect LDAP server type from LDIF file or content."""
            ...

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
            Mapping[
                str,
                FlextLdifProtocolsDomain.SchemaServer
                | FlextLdifProtocolsDomain.AclServer
                | FlextLdifProtocolsDomain.EntryServer,
            ]
        ]: ...

        def resolve_server_constants(
            self, server_type: str
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]: ...

        def list_registered_servers(self) -> p.Result[MutableSequence[str]]: ...

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
        CATEGORIZATION_PRIORITY: ClassVar[Sequence[str]]
        CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping]
        HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]]
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]]

    @runtime_checkable
    class SchemaItemKind(Protocol):
        """Schema item kind enumeration."""

        ATTRIBUTE: str
        OBJECTCLASS: str

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
            Mapping[
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

        def list_registered_servers(self) -> p.Result[MutableSequence[str]]:
            """List registered server types via the facade DSL."""
            ...

        def summarize_registry(self) -> p.Result[t.MutableJsonMapping]:
            """Return registry summary metadata via the facade DSL."""
            ...

        def resolve_supported_conversions(
            self,
            server: FlextLdifProtocolsBase.ServerReference | str,
        ) -> Mapping[str, bool]:
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
            model_instance: FlextLdifProtocolsDomainEntry.Entry
            | FlextLdifProtocolsDomainSchema.SchemaAttribute
            | FlextLdifProtocolsDomainSchema.SchemaObjectClass
            | FlextLdifProtocolsDomainAcl.Acl,
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
    class MetadataWithWriteOptions(Protocol):
        """Metadata payload that may carry embedded write options."""

        @property
        def write_options(self) -> FlextLdifProtocolsDomainMetadata.WriteOptions | None:
            """The embedded write options."""
            ...

    @runtime_checkable
    class Predicate[T](Protocol):
        """Predicate function contract."""

        def __call__(self, item: T) -> bool:
            """Return whether the item matches the predicate."""
            ...

    @runtime_checkable
    class RegistryPortOptions(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        registry: p.Registry


__all__: list[str] = ["FlextLdifProtocolsBase"]
