"""CQRS Handler Implementations for FLEXT-LDIF.

This module provides handler classes that process commands and queries
by delegating to domain services (client, builders, validators).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextCore

from flext_ldif.models import FlextLdifModels

if TYPE_CHECKING:
    from flext_ldif.client import FlextLdifClient
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
    from flext_ldif.entry.builder import FlextLdifEntryBuilder


class ParseLdifCommandHandler:
    """Handler for ParseLdifCommand."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, command: ParseLdifCommand
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Handle parse LDIF command."""
        return self._client.parse_ldif(command.source, command.server_type)


class WriteLdifCommandHandler:
    """Handler for WriteLdifCommand."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(self, command: WriteLdifCommand) -> FlextCore.Result[str]:
        """Handle write LDIF command."""
        return self._client.write_ldif(command.entries, command.output_path)


class MigrateLdifCommandHandler:
    """Handler for MigrateLdifCommand."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, command: MigrateLdifCommand
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle migrate LDIF command."""
        return self._client.migrate_files(
            command.input_dir,
            command.output_dir,
            command.from_server,
            command.to_server,
            process_schema=command.process_schema,
            process_entries=command.process_entries,
        )


class BuildPersonEntryCommandHandler:
    """Handler for BuildPersonEntryCommand."""

    def __init__(self, entry_builder: FlextLdifEntryBuilder) -> None:
        """Initialize handler with entry builder."""
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
    """Handler for BuildGroupEntryCommand."""

    def __init__(self, entry_builder: FlextLdifEntryBuilder) -> None:
        """Initialize handler with entry builder."""
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
    """Handler for BuildOrganizationalUnitCommand."""

    def __init__(self, entry_builder: FlextLdifEntryBuilder) -> None:
        """Initialize handler with entry builder."""
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
    """Handler for ValidateEntriesQuery."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, query: ValidateEntriesQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle validate entries query."""
        return self._client.validate_entries(query.entries)


class AnalyzeEntriesQueryHandler:
    """Handler for AnalyzeEntriesQuery."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, query: AnalyzeEntriesQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle analyze entries query."""
        return self._client.analyze_entries(query.entries)


class FilterEntriesQueryHandler:
    """Handler for FilterEntriesQuery."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, query: FilterEntriesQuery
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Handle filter entries query."""
        if query.objectclass:
            return self._client.filter_by_objectclass(query.entries, query.objectclass)
        # Default: return all entries if no filters specified
        return FlextCore.Result[list[FlextLdifModels.Entry]].ok(query.entries)


class ExtractAclsQueryHandler:
    """Handler for ExtractAclsQuery."""

    def __init__(self, client: FlextLdifClient) -> None:
        """Initialize handler with LDIF client."""
        self._client = client

    def handle(
        self, query: ExtractAclsQuery
    ) -> FlextCore.Result[list[FlextLdifModels.Acl]]:
        """Handle extract ACLs query."""
        _ = query  # Reserved for future ACL extraction implementation
        # Note: This requires ACL service from container
        # For now, return empty result as ACL extraction is complex
        return FlextCore.Result[list[FlextLdifModels.Acl]].ok([])


class ConvertEntryToDictQueryHandler:
    """Handler for ConvertEntryToDictQuery."""

    def __init__(self, entry_builder: FlextLdifEntryBuilder) -> None:
        """Initialize handler with entry builder."""
        self._entry_builder = entry_builder

    def handle(
        self, query: ConvertEntryToDictQuery
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Handle convert entry to dict query."""
        return self._entry_builder.convert_entry_to_dict(query.entry)


class ConvertEntriesToDictsQueryHandler:
    """Handler for ConvertEntriesToDictsQuery."""

    def __init__(self, entry_builder: FlextLdifEntryBuilder) -> None:
        """Initialize handler with entry builder."""
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
