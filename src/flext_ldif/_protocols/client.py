"""Public LDIF client and settings contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_cli import p, t

from flext_ldif import c
from flext_ldif._protocols import FlextLdifProtocolsBase, FlextLdifProtocolsValues

if TYPE_CHECKING:
    from collections.abc import Sequence
    from os import PathLike
    from pathlib import Path

    from flext_ldif import m


@runtime_checkable
class FlextLdifProtocolsClient(Protocol):
    """Client-facing contracts composed above base and domain declarations."""

    @runtime_checkable
    class ProcessingPipeline(
        p.Service[t.SequenceOf[FlextLdifProtocolsValues.Entry]], Protocol
    ):
        """Runtime-bound entry transformations and their declared configuration."""

        registry: t.Port[p.Registry]

        @property
        def transform_config(
            self,
        ) -> FlextLdifProtocolsValues.TransformConfig | None: ...

        @property
        def entries_input(
            self,
        ) -> t.SequenceOf[FlextLdifProtocolsValues.Entry] | None: ...

        @classmethod
        def for_servers(
            cls,
            *,
            registry: p.Registry,
            runtime_settings: FlextLdifProtocolsBase.Settings | None = None,
            source_server: str | c.Ldif.ServerTypes,
            target_server: str | c.Ldif.ServerTypes,
            base_dn: str = "",
        ) -> Self:
            """Construct a pipeline using the supplied registry and dialects."""
            ...

    @runtime_checkable
    class MigrationPipeline(
        p.Service[FlextLdifProtocolsValues.MigrationPipelineResult], Protocol
    ):
        """Runtime-bound migration operations and their declared configuration."""

        registry: t.Port[p.Registry]
        input_dir: Path | None
        output_dir: Path | None
        output_filename: str | None
        source_server_type: c.Ldif.ServerTypes
        target_server_type: c.Ldif.ServerTypes
        base_dn: str

        def migrate_entries(
            self, entries: t.SequenceOf[FlextLdifProtocolsValues.Entry]
        ) -> p.Result[t.SequenceOf[FlextLdifProtocolsValues.Entry]]:
            """Migrate the supplied entries through the bound registry."""
            ...

        def migrate_file(
            self,
            input_file: PathLike[str],
            output_file: PathLike[str] | None = None,
        ) -> p.Result[FlextLdifProtocolsValues.MigrationPipelineResult]:
            """Read, migrate and write one file through the public service."""
            ...

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
        def settings(self) -> FlextLdifProtocolsBase.Settings:
            """The validated runtime settings carried by the facade."""
            ...

        def migrate(
            self,
            input_dir: Path | None = None,
            output_dir: Path | None = None,
            source_server: str = c.Ldif.ServerTypes.RFC.value,
            target_server: str = c.Ldif.ServerTypes.RFC.value,
            options: FlextLdifProtocolsBase.MigrationOutputOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsValues.MigrationPipelineResult]:
            """Run the public LDIF migration pipeline."""
            ...

        def parse_ldif(
            self,
            value: str | PathLike[str],
            *,
            server_type: str | None = None,
        ) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF content from text or a file path."""
            ...

        def parse_ldif_file(
            self,
            path: PathLike[str],
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
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a response."""
            ...

        def write_ldif_file(
            self,
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            path: PathLike[str],
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a file."""
            ...

        def write_to_string(
            self,
            entries: Sequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write canonical LDIF entries to text."""
            ...

        def validate_entries(
            self,
            entries: Sequence[FlextLdifProtocolsValues.Entry]
            | FlextLdifProtocolsValues.ParseResponse,
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
            entry: FlextLdifProtocolsValues.Entry,
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
            entries: Sequence[FlextLdifProtocolsValues.Entry],
            options: FlextLdifProtocolsBase.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.ProcessingResult]]:
            """Process entries through the public facade."""
            ...

        def calculate_for_entries(
            self,
            entries: Sequence[FlextLdifProtocolsValues.Entry]
            | FlextLdifProtocolsValues.ParseResponse,
        ) -> p.Result[FlextLdifProtocolsBase.EntriesStatistics]:
            """Calculate aggregate entry statistics."""
            ...

    @runtime_checkable
    class LdifClient(
        FlextLdifProtocolsBase.ValidationService,
        FlextLdifProtocolsBase.ServerDetectionService,
        FlextLdifProtocolsBase.ServerResolutionService,
        Protocol,
    ):
        """Protocol for LDIF clients that support CRUD operations."""

        @property
        def settings(self) -> FlextLdifProtocolsBase.Settings:
            """Expose the typed LDIF settings carried by the public facade."""
            ...

        def migrate(
            self,
            input_dir: Path | None = None,
            output_dir: Path | None = None,
            source_server: str = "rfc",
            target_server: str = "rfc",
            options: FlextLdifProtocolsBase.MigrationOutputOptions | None = None,
        ) -> p.Result[FlextLdifProtocolsValues.MigrationPipelineResult]:
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
            entries: t.SequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to text response."""
            ...

        def write_ldif_file(
            self,
            entries: t.SequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            path: Path,
            *,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[m.Ldif.WriteResponse]:
            """Write canonical LDIF entries to a file."""
            ...

        def write_to_string(
            self,
            entries: t.SequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
            server_type: str | None = None,
            format_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write LDIF entries to a string."""
            ...

        def validate_entries(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsValues.Entry]
            | FlextLdifProtocolsValues.ParseResponse,
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
            entry: FlextLdifProtocolsValues.Entry,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.AclResponse]:
            """Extract ACLs from an entry through the public facade DSL."""
            ...

        def evaluate_acl_context(
            self,
            acls: t.SequenceOf[FlextLdifProtocolsBase.Acl],
            required_permissions: FlextLdifProtocolsBase.AclPermissions
            | t.MutableBoolMapping,
        ) -> p.Result[FlextLdifProtocolsBase.AclEvaluationResult]:
            """Evaluate ACLs through the public facade DSL."""
            ...

        def process_entries(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsValues.Entry],
            options: FlextLdifProtocolsBase.ProcessEntriesOptions | None = None,
            **kwargs: t.JsonValue,
        ) -> p.Result[t.MutableSequenceOf[FlextLdifProtocolsBase.ProcessingResult]]:
            """Process entries through the public facade DSL."""
            ...

        def calculate_for_entries(
            self,
            entries: t.SequenceOf[FlextLdifProtocolsValues.Entry]
            | FlextLdifProtocolsValues.ParseResponse,
        ) -> p.Result[FlextLdifProtocolsBase.EntriesStatistics]:
            """Calculate entry statistics through the public facade DSL."""
            ...


__all__: list[str] = ["FlextLdifProtocolsClient"]
