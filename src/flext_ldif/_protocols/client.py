"""Public LDIF client and settings contracts."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from flext_cli import p, t
from flext_ldif._protocols.base import FlextLdifProtocolsBase
from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
from flext_ldif.constants import c

# NOTE (multi-agent, mro-0ftd.3.7.2): client declarations are the highest
# private protocol facet and may depend one-way on both base and domain.


@runtime_checkable
class FlextLdifProtocolsClient(Protocol):
    """Client-facing contracts composed above base and domain declarations."""

    @runtime_checkable
    class LdifSettings(Protocol):
        """Namespaced LDIF runtime settings branch."""

        @property
        def ldif_encoding(self) -> c.Ldif.Encoding | str:
            """Default encoding for LDIF read/write operations."""
            ...

        @property
        def ldif_strict_validation(self) -> bool:
            """Whether strict LDIF validation is enabled."""
            ...

    @runtime_checkable
    class Settings(p.Cli.Settings, Protocol):
        """MRO-composed settings contract with the LDIF namespace."""

        Ldif: FlextLdifProtocolsClient.LdifSettings
        """The validated LDIF settings branch."""

    @runtime_checkable
    class Client(
        FlextLdifProtocolsBase.ValidationService,
        FlextLdifProtocolsBase.ServerDetectionService,
        Protocol,
    ):
        """Public contract for the composed LDIF facade."""

        @property
        def settings(self) -> FlextLdifProtocolsClient.Settings:
            """The validated runtime settings carried by the facade."""
            ...

        def migrate(
            self,
            input_dir: Path | None = None,
            output_dir: Path | None = None,
            source_server: str = c.Ldif.ServerTypes.RFC.value,
            target_server: str = c.Ldif.ServerTypes.RFC.value,
            options: FlextLdifProtocolsBase.MigrateOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Run the public LDIF migration pipeline."""
            ...

        def parse_ldif(
            self,
            value: str | Path,
            *,
            server_type: str | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ParseResponse]:
            """Parse LDIF content from text or a file path."""
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
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.WriteResponse]:
            """Write canonical LDIF entries to a response."""
            ...

        def write_ldif_file(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
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
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            server_type: str | None = None,
            format_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write canonical LDIF entries to text."""
            ...

        def acl(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.AclServer]:
            """Resolve an ACL server by server type."""
            ...

        def entry(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.EntryServer]:
            """Resolve an entry server by server type."""
            ...

        def resolve_base_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]:
            """Resolve a base server by server type."""
            ...

        def schema_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]:
            """Resolve a schema server by server type."""
            ...

        def resolve_schema_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.SchemaServer]:
            """Resolve the canonical schema server by server type."""
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
            """Resolve the schema, ACL, and entry server bundle."""
            ...

        def resolve_server_constants(
            self,
            server_type: str,
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]:
            """Resolve server constants by server type."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): mutable element type matches the
        # public facade (api.py:223) and concrete registry SSOT (server.py:160).
        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
            """List normalized registered server types."""
            ...

        def summarize_registry(self) -> p.Result[t.MutableJsonMapping]:
            """Summarize the server registry."""
            ...

        def resolve_supported_conversions(
            self,
            server: FlextLdifProtocolsBase.ServerReference | str,
        ) -> t.MappingKV[str, bool]:
            """Return conversion capabilities for a server."""
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
        ) -> p.Result[
            FlextLdifProtocolsBase.Entry
            | FlextLdifProtocolsBase.SchemaAttribute
            | FlextLdifProtocolsBase.SchemaObjectClass
            | FlextLdifProtocolsBase.Acl
        ]:
            """Convert one LDIF model between server implementations."""
            ...

        def resolve_effective_server_type(
            self,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
        ) -> p.Result[str]:
            """Resolve the effective LDAP server type."""
            ...

        def validate_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            validation_service: FlextLdifProtocolsBase.ValidationService | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ValidationResult]:
            """Validate a canonical entry batch."""
            ...

        def service_check(self) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Run the public ACL service wiring check."""
            ...

        def parse_acl_string(
            self,
            acl_string: str,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.Acl]:
            """Parse one ACL string."""
            ...

        def extract_acls_from_entry(
            self,
            entry: FlextLdifProtocolsBase.Entry,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Extract ACLs from one canonical entry."""
            ...

        @staticmethod
        def evaluate_acl_context(
            acls: Sequence[FlextLdifProtocolsBase.Acl],
            required_permissions: FlextLdifProtocolsBase.AclPermissions
            | t.MutableBoolMapping,
        ) -> p.Result[FlextLdifProtocolsBase.AclEvaluationResult]:
            """Evaluate ACLs against the required permissions."""
            ...

        def process_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry],
            options: FlextLdifProtocolsBase.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.ProcessingResult]]:
            """Process entries through the public facade."""
            ...

        def calculate_for_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
        ) -> p.Result[FlextLdifProtocolsBase.EntriesStatistics]:
            """Calculate aggregate entry statistics."""
            ...


__all__: list[str] = ["FlextLdifProtocolsClient"]
