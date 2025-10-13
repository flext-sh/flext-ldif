"""CQRS Infrastructure for FLEXT-LDIF.

This package provides Command Query Responsibility Segregation (CQRS) patterns for LDIF operations.
Separates write operations (commands) from read operations (queries) with dedicated handlers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.cqrs.commands import (
    BuildGroupEntryCommand,
    BuildOrganizationalUnitCommand,
    BuildPersonEntryCommand,
    MigrateLdifCommand,
    ParseLdifCommand,
    WriteLdifCommand,
)
from flext_ldif.cqrs.handlers import (
    AnalyzeEntriesQueryHandler,
    BuildGroupEntryCommandHandler,
    BuildOrganizationalUnitCommandHandler,
    BuildPersonEntryCommandHandler,
    ConvertEntriesToDictsQueryHandler,
    ConvertEntryToDictQueryHandler,
    ExtractAclsQueryHandler,
    FilterEntriesQueryHandler,
    MigrateLdifCommandHandler,
    ParseLdifCommandHandler,
    ValidateEntriesQueryHandler,
    WriteLdifCommandHandler,
)
from flext_ldif.cqrs.queries import (
    AnalyzeEntriesQuery,
    ConvertEntriesToDictsQuery,
    ConvertEntryToDictQuery,
    ExtractAclsQuery,
    FilterEntriesQuery,
    ValidateEntriesQuery,
)

__all__ = [
    "AnalyzeEntriesQuery",
    "AnalyzeEntriesQueryHandler",
    "BuildGroupEntryCommand",
    "BuildGroupEntryCommandHandler",
    "BuildOrganizationalUnitCommand",
    "BuildOrganizationalUnitCommandHandler",
    "BuildPersonEntryCommand",
    "BuildPersonEntryCommandHandler",
    "ConvertEntriesToDictsQuery",
    "ConvertEntriesToDictsQueryHandler",
    "ConvertEntryToDictQuery",
    "ConvertEntryToDictQueryHandler",
    "ExtractAclsQuery",
    "ExtractAclsQueryHandler",
    "FilterEntriesQuery",
    "FilterEntriesQueryHandler",
    "MigrateLdifCommand",
    "MigrateLdifCommandHandler",
    "ParseLdifCommand",
    "ParseLdifCommandHandler",
    "ValidateEntriesQuery",
    "ValidateEntriesQueryHandler",
    "WriteLdifCommand",
    "WriteLdifCommandHandler",
]
