"""CQRS Handler Implementations for FLEXT-LDIF.

This module provides handler classes that process commands and queries
by delegating to application protocols (processor, builder interfaces).

Clean Architecture: Application layer depends ONLY on protocols, not implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextCore

from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

# Application Layer Constants
_MAX_PATH_LENGTH_CHECK = 1024  # Maximum string length to check if it's a file path

if TYPE_CHECKING:
    from flext_ldif.cqrs.commands import (
        BuildGroupEntryCommand,
        BuildOrganizationalUnitCommand,
        BuildPersonEntryCommand,
        MigrateLdifCommand,
        ParseLdifCommand,
        WriteLdifCommand,
    )
    from flext_ldif.cqrs.queries import (
        AnalyzeEntriesQuery,
        ConvertEntriesToDictsQuery,
        ConvertEntryToDictQuery,
        ExtractAclsQuery,
        FilterEntriesQuery,
        ValidateEntriesQuery,
    )


class ParseLdifCommandHandler:
    """Handler for ParseLdifCommand.

    Application Layer: Depends on ProcessorProtocol (interface), not concrete client.
    """

    def __init__(self, processor: FlextLdifProtocols.Ldif.ProcessorProtocol) -> None:
        """Initialize handler with LDIF processor protocol.

        Args:
            processor: Object implementing ProcessorProtocol interface

        """
        self._processor = processor

    def handle(
        self, command: ParseLdifCommand
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Handle parse LDIF command.

        Application Logic: Determine if source is file or content, delegate to processor.
        """
        # Note: server_type parameter reserved for future quirk-based parsing
        _ = command.server_type  # Suppress unused argument warning

        # If source is a Path, use parse_ldif_file
        if isinstance(command.source, Path):
            return self._processor.parse_ldif_file(command.source)

        # If source is a string that looks like a file path, convert to Path
        if (
            isinstance(command.source, str)
            and "\n" not in command.source
            and len(command.source) < _MAX_PATH_LENGTH_CHECK
        ):
            potential_path = Path(command.source)
            if potential_path.exists() and potential_path.is_file():
                return self._processor.parse_ldif_file(potential_path)

        # Otherwise, parse as content string
        return self._processor.parse_content(command.source)


class WriteLdifCommandHandler:
    """Handler for WriteLdifCommand.

    Application Layer: Depends on ProcessorProtocol (interface), not concrete client.
    """

    def __init__(self, processor: FlextLdifProtocols.Ldif.ProcessorProtocol) -> None:
        """Initialize handler with LDIF processor protocol.

        Args:
            processor: Object implementing ProcessorProtocol interface

        """
        self._processor = processor

    def handle(self, command: WriteLdifCommand) -> FlextCore.Result[str]:
        """Handle write LDIF command.

        Application Logic: Write entries to LDIF string, optionally save to file.
        """
        # Write entries to LDIF string using processor
        result = self._processor.write(command.entries)
        if result.is_failure:
            return result

        # If output_path specified, write to file
        if command.output_path:
            try:
                content = result.unwrap()
                command.output_path.write_text(content, encoding="utf-8")
                return FlextCore.Result[str].ok(
                    f"Successfully wrote {len(command.entries)} entries to {command.output_path}"
                )
            except Exception as e:
                return FlextCore.Result[str].fail(
                    f"Failed to write to file {command.output_path}: {e}"
                )

        return result


class MigrateLdifCommandHandler:
    """Handler for MigrateLdifCommand.

    Application Layer: Delegates to migration pipeline (infrastructure).
    Note: This handler bridges application and infrastructure layers.
    """

    def __init__(
        self, migration_pipeline: FlextLdifProtocols.Ldif.MigrationPipelineProtocol
    ) -> None:
        """Initialize handler with migration pipeline protocol.

        Args:
            migration_pipeline: Object implementing MigrationPipelineProtocol

        """
        self._migration_pipeline = migration_pipeline

    def handle(
        self, command: MigrateLdifCommand
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle migrate LDIF command.

        Application Logic: Orchestrate file-based LDIF migration.
        """
        # Note: This uses infrastructure directly (file operations)
        # In a pure Clean Architecture, this would use a repository abstraction
        try:
            params: FlextCore.Types.Dict = {
                "input_dir": str(command.input_dir),
                "output_dir": str(command.output_dir),
                "process_schema": command.process_schema,
                "process_entries": command.process_entries,
            }

            pipeline = FlextLdifMigrationPipeline(
                params=params,
                source_server_type=command.from_server,
                target_server_type=command.to_server,
            )

            return pipeline.execute()

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(f"Migration failed: {e}")


class BuildPersonEntryCommandHandler:
    """Handler for BuildPersonEntryCommand.

    Application Layer: Depends on EntryBuilderProtocol (interface), not concrete builder.
    """

    def __init__(
        self, entry_builder: FlextLdifProtocols.Ldif.EntryBuilderProtocol
    ) -> None:
        """Initialize handler with entry builder protocol.

        Args:
            entry_builder: Object implementing EntryBuilderProtocol interface

        """
        self._entry_builder = entry_builder

    def handle(
        self, command: BuildPersonEntryCommand
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Handle build person entry command."""
        return self._entry_builder.build_person_entry(
            command.cn,
            command.sn,
            command.base_dn,
            command.uid,
            command.mail,
            command.given_name,
            command.additional_attrs,
        )


class BuildGroupEntryCommandHandler:
    """Handler for BuildGroupEntryCommand.

    Application Layer: Depends on EntryBuilderProtocol (interface), not concrete builder.
    """

    def __init__(
        self, entry_builder: FlextLdifProtocols.Ldif.EntryBuilderProtocol
    ) -> None:
        """Initialize handler with entry builder protocol.

        Args:
            entry_builder: Object implementing EntryBuilderProtocol interface

        """
        self._entry_builder = entry_builder

    def handle(
        self, command: BuildGroupEntryCommand
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Handle build group entry command."""
        return self._entry_builder.build_group_entry(
            command.cn,
            command.base_dn,
            command.members,
            command.description,
            command.additional_attrs,
        )


class BuildOrganizationalUnitCommandHandler:
    """Handler for BuildOrganizationalUnitCommand.

    Application Layer: Depends on EntryBuilderProtocol (interface), not concrete builder.
    """

    def __init__(
        self, entry_builder: FlextLdifProtocols.Ldif.EntryBuilderProtocol
    ) -> None:
        """Initialize handler with entry builder protocol.

        Args:
            entry_builder: Object implementing EntryBuilderProtocol interface

        """
        self._entry_builder = entry_builder

    def handle(
        self, command: BuildOrganizationalUnitCommand
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Handle build organizational unit command."""
        return self._entry_builder.build_organizational_unit_entry(
            command.ou,
            command.base_dn,
            command.description,
            command.additional_attrs,
        )


class ValidateEntriesQueryHandler:
    """Handler for ValidateEntriesQuery.

    Application Layer: Depends on ProcessorProtocol (interface), not concrete client.
    """

    def __init__(self, processor: FlextLdifProtocols.Ldif.ProcessorProtocol) -> None:
        """Initialize handler with LDIF processor protocol.

        Args:
            processor: Object implementing ProcessorProtocol interface

        """
        self._processor = processor

    def handle(
        self, query: ValidateEntriesQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle validate entries query.

        Application Logic: Validate entries and return dict with results.
        """
        # Note: ProcessorProtocol.validate_entries returns list[Entry]
        # We need to adapt this to return a Dict with validation info
        result = self._processor.validate_entries(query.entries)
        if result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                result.error or "Validation failed"
            )

        validated_entries = result.unwrap()
        return FlextCore.Result[FlextCore.Types.Dict].ok({
            "is_valid": len(validated_entries) == len(query.entries),
            "total_entries": len(query.entries),
            "valid_entries": len(validated_entries),
            "invalid_entries": len(query.entries) - len(validated_entries),
        })


class AnalyzeEntriesQueryHandler:
    """Handler for AnalyzeEntriesQuery.

    Application Layer: Depends on ProcessorProtocol (interface), not concrete client.
    """

    def __init__(self, processor: FlextLdifProtocols.Ldif.ProcessorProtocol) -> None:
        """Initialize handler with LDIF processor protocol.

        Args:
            processor: Object implementing ProcessorProtocol interface

        """
        self._processor = processor

    def handle(
        self, query: AnalyzeEntriesQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle analyze entries query."""
        return self._processor.analyze_entries(query.entries)


class FilterEntriesQueryHandler:
    """Handler for FilterEntriesQuery.

    Application Layer: Pure application logic (no infrastructure dependencies).
    """

    def __init__(self) -> None:
        """Initialize handler (no dependencies)."""

    def handle(
        self, query: FilterEntriesQuery
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Handle filter entries query.

        Application Logic: Filter entries by objectClass.
        """
        if query.objectclass:
            # Filter entries using domain logic (list comprehension for performance)
            filtered = [
                entry
                for entry in query.entries
                if entry.has_object_class(query.objectclass)
            ]
            return FlextCore.Result[list[FlextLdifModels.Entry]].ok(filtered)

        # Default: return all entries if no filters specified
        return FlextCore.Result[list[FlextLdifModels.Entry]].ok(query.entries)


class ExtractAclsQueryHandler:
    """Handler for ExtractAclsQuery.

    Application Layer: Reserved for future ACL extraction (requires ACL service protocol).
    """

    def __init__(self) -> None:
        """Initialize handler (no dependencies yet)."""

    def handle(
        self, query: ExtractAclsQuery
    ) -> FlextCore.Result[list[FlextLdifModels.Acl]]:
        """Handle extract ACLs query."""
        _ = query  # Reserved for future ACL extraction implementation
        # Note: This requires ACL service protocol
        # For now, return empty result as ACL extraction is complex
        return FlextCore.Result[list[FlextLdifModels.Acl]].ok([])


class ConvertEntryToDictQueryHandler:
    """Handler for ConvertEntryToDictQuery.

    Application Layer: Depends on EntryBuilderProtocol (interface), not concrete builder.
    """

    def __init__(
        self, entry_builder: FlextLdifProtocols.Ldif.EntryBuilderProtocol
    ) -> None:
        """Initialize handler with entry builder protocol.

        Args:
            entry_builder: Object implementing EntryBuilderProtocol interface

        """
        self._entry_builder = entry_builder

    def handle(
        self, query: ConvertEntryToDictQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle convert entry to dict query."""
        return self._entry_builder.convert_entry_to_dict(query.entry)


class ConvertEntriesToDictsQueryHandler:
    """Handler for ConvertEntriesToDictsQuery.

    Application Layer: Depends on EntryBuilderProtocol (interface), not concrete builder.
    """

    def __init__(
        self, entry_builder: FlextLdifProtocols.Ldif.EntryBuilderProtocol
    ) -> None:
        """Initialize handler with entry builder protocol.

        Args:
            entry_builder: Object implementing EntryBuilderProtocol interface

        """
        self._entry_builder = entry_builder

    def handle(
        self, query: ConvertEntriesToDictsQuery
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Handle convert entries to dicts query."""
        results: list[FlextCore.Types.Dict] = []
        for entry in query.entries:
            result = self._entry_builder.convert_entry_to_dict(entry)
            if result.is_success:
                results.append(result.unwrap())
        return FlextCore.Result[list[FlextCore.Types.Dict]].ok(results)


__all__ = [
    "AnalyzeEntriesQueryHandler",
    "BuildGroupEntryCommandHandler",
    "BuildOrganizationalUnitCommandHandler",
    "BuildPersonEntryCommandHandler",
    "ConvertEntriesToDictsQueryHandler",
    "ConvertEntryToDictQueryHandler",
    "ExtractAclsQueryHandler",
    "FilterEntriesQueryHandler",
    "MigrateLdifCommandHandler",
    "ParseLdifCommandHandler",
    "ValidateEntriesQueryHandler",
    "WriteLdifCommandHandler",
]
