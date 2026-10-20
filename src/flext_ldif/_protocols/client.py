"""Public LDIF client and settings contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_cli import p, t

from flext_ldif import c
from flext_ldif._protocols import FlextLdifProtocolsBase

if TYPE_CHECKING:
    from collections.abc import Sequence
    from os import PathLike
    from pathlib import Path

    from flext_ldif import m
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


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

        @property
        def ldif(self) -> FlextLdifProtocolsClient.LdifSettings:
            """Namespaced LDIF settings branch."""
            ...

    @runtime_checkable
    class ProcessingPipeline(
        p.Service[t.SequenceOf[FlextLdifProtocolsBase.Entry]], Protocol
    ):
        """Runtime-bound entry transformations and their declared configuration."""

        registry: t.Port[p.Registry]
        runtime_settings: FlextLdifProtocolsClient.Settings | None
        transform_config: FlextLdifProtocolsValues.TransformConfig | None
        entries_input: t.SequenceOf[FlextLdifProtocolsBase.Entry] | None

        @classmethod
        def for_servers(
            cls,
            *,
            registry: p.Registry,
            runtime_settings: FlextLdifProtocolsClient.Settings | None = None,
            source_server: str | c.Ldif.ServerTypes,
            target_server: str | c.Ldif.ServerTypes,
            base_dn: str = "",
        ) -> Self:
            """Construct a pipeline using the supplied registry and dialects."""
            del base_dn, registry, runtime_settings, source_server, target_server

    @runtime_checkable
    class MigrationPipeline(
        p.Service[FlextLdifProtocolsBase.MigrationPipelineResult], Protocol
    ):
        """Runtime-bound migration operations and their declared configuration."""

        registry: t.Port[p.Registry]
        runtime_settings: FlextLdifProtocolsClient.Settings | None
        input_dir: Path | None
        output_dir: Path | None
        output_filename: str | None
        mode: str | None
        source_server: str | c.Ldif.ServerTypes | None
        target_server: str | c.Ldif.ServerTypes | None
        source_server_type: str | c.Ldif.ServerTypes | None
        target_server_type: str | c.Ldif.ServerTypes | None
        base_dn: str | None

        def migrate_entries(
            self, entries: t.SequenceOf[FlextLdifProtocolsBase.Entry]
        ) -> p.Result[t.SequenceOf[FlextLdifProtocolsBase.Entry]]:
            """Migrate the supplied entries through the bound registry."""
            del entries

        def migrate_file(
            self,
            input_file: PathLike[str],
            output_file: PathLike[str] | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Read, migrate and write one file through the public service."""
            del input_file, output_file

    @runtime_checkable
    class Client(
        FlextLdifProtocolsBase.ValidationService,
        FlextLdifProtocolsBase.ServerDetectionService,
        FlextLdifProtocolsBase.ServerResolutionService,
        Protocol,
    ):
        """Public contract for the composed LDIF facade.

        ``ServerResolutionService`` has a single owner in
        ``FlextLdifProtocolsBase`` and is composed unchanged.
        """

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
            options: FlextLdifProtocolsBase.MigrationOutputOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Run the public LDIF migration pipeline."""
            del input_dir, options, output_dir, source_server, target_server

        def parse_ldif(
            self,
            value: str | PathLike[str],
            *,
            server_type: str | None = None,
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from text or a file path."""
            del server_type, value

        def parse_ldif_file(
            self,
            path: PathLike[str],
            server_type: str | None = None,
            encoding: str = "utf-8",
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from a file path."""
            del encoding, path, server_type

        def parse_string(
            self,
            content: str,
            server_type: str | None = None,
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from a raw string."""
            del content, server_type

        def write(
            self,
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a response."""
            del entries, format_options, server_type

        def write_ldif_file(
            self,
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            path: PathLike[str],
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a file."""
            del entries, format_options, path, server_type

        def write_to_string(
            self,
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write canonical LDIF entries to text."""
            del entries, format_options, server_type

        def validate_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
            validation_service: FlextLdifProtocolsBase.ValidationService | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ValidationResult]:
            """Validate a canonical entry batch."""
            del entries, validation_service

        def service_check(self) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Run the public ACL service wiring check."""
            ...

        def parse_acl_string(
            self,
            acl_string: str,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.Acl]:
            """Parse one ACL string."""
            del acl_string, server_type

        def extract_acls_from_entry(
            self,
            entry: FlextLdifProtocolsBase.Entry,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Extract ACLs from one canonical entry."""
            del entry, server_type

        @staticmethod
        def evaluate_acl_context(
            acls: Sequence[FlextLdifProtocolsBase.Acl],
            required_permissions: FlextLdifProtocolsBase.AclPermissions
            | t.MutableBoolMapping,
        ) -> p.Result[FlextLdifProtocolsBase.AclEvaluationResult]:
            """Evaluate ACLs against the required permissions."""
            del acls, required_permissions

        def process_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry],
            options: FlextLdifProtocolsBase.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.ProcessingResult]]:
            """Process entries through the public facade."""
            del entries, kwargs, options

        def calculate_for_entries(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
        ) -> p.Result[FlextLdifProtocolsBase.EntriesStatistics]:
            """Calculate aggregate entry statistics."""
            del entries


__all__: list[str] = ["FlextLdifProtocolsClient"]
