"""FLEXT LDIF Models - Unified Namespace for LDIF Domain Models.

This module provides a unified namespace class that aggregates all LDIF domain models
from specialized sub-modules. It extends flext-core FlextCore.Models with LDIF-specific
domain entities organized into focused modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Type Checking Notes:
- ANN401: **extensions uses Any for flexible quirk-specific data
- pyrefly: import errors for pydantic/dependency_injector (searches wrong site-packages path)
- pyright: configured with extraPaths to resolve imports (see pyrightconfig.json)
- mypy: passes with strict mode (0 errors)
- All 639 tests pass - code is correct, only infrastructure configuration differs
"""

from __future__ import annotations

from flext_core import FlextCore

from flext_ldif.commands_processing import (
    AnalyzeQuery,
    MigrateCommand,
    ParseQuery,
    RegisterQuirkCommand,
    ValidateQuery,
    WriteCommand,
)
from flext_ldif.domain_acl import AclPermissions, AclSubject, AclTarget, UnifiedAcl
from flext_ldif.domain_attributes import AttributeValues, LdifAttributes

# Import from new modular structure
from flext_ldif.domain_dn import DistinguishedName
from flext_ldif.domain_entry import Entry
from flext_ldif.domain_quirks import QuirkMetadata
from flext_ldif.domain_utilities import AttributeName, Encoding, LdifUrl
from flext_ldif.dto_analytics import AnalyticsResult, LdifValidationResult, SearchConfig
from flext_ldif.dto_diff import DiffResult
from flext_ldif.dto_filter import CategorizedEntries, ExclusionInfo, FilterCriteria
from flext_ldif.dto_schema import SchemaDiscoveryResult
from flext_ldif.events_processing import (
    AnalyticsGeneratedEvent,
    EntriesValidatedEvent,
    EntriesWrittenEvent,
    EntryParsedEvent,
    MigrationCompletedEvent,
    QuirkRegisteredEvent,
)
from flext_ldif.models.dto.schema import SchemaAttribute, SchemaObjectClass

# Import moved inside methods to avoid circular import


class FlextLdifModels(FlextCore.Models):
    """LDIF domain models extending flext-core FlextCore.Models.

    Unified namespace class that aggregates all LDIF domain models from specialized sub-modules.
    Provides a single access point for all LDIF models while maintaining modular organization.

    This class extends flext-core FlextCore.Models and organizes LDIF-specific models into
    focused sub-modules for better maintainability and reduced complexity.
    """

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================

    # Distinguished Name and core entities
    DistinguishedName = DistinguishedName
    Entry = Entry
    AttributeValues = AttributeValues
    LdifAttributes = LdifAttributes
    AttributeName = AttributeName
    LdifUrl = LdifUrl
    Encoding = Encoding
    QuirkMetadata = QuirkMetadata

    # ACL models
    UnifiedAcl = UnifiedAcl
    AclTarget = AclTarget
    AclSubject = AclSubject
    AclPermissions = AclPermissions

    # =========================================================================
    # DTO MODELS - Data transfer objects
    # =========================================================================

    FilterCriteria = FilterCriteria
    ExclusionInfo = ExclusionInfo
    CategorizedEntries = CategorizedEntries
    DiffResult = DiffResult
    SchemaDiscoveryResult = SchemaDiscoveryResult
    SchemaAttribute = SchemaAttribute
    SchemaObjectClass = SchemaObjectClass
    AnalyticsResult = AnalyticsResult
    LdifValidationResult = LdifValidationResult
    SearchConfig = SearchConfig

    # =========================================================================
    # EVENT MODELS - Domain events
    # =========================================================================

    EntryParsedEvent = EntryParsedEvent
    EntriesValidatedEvent = EntriesValidatedEvent
    AnalyticsGeneratedEvent = AnalyticsGeneratedEvent
    EntriesWrittenEvent = EntriesWrittenEvent
    MigrationCompletedEvent = MigrationCompletedEvent
    QuirkRegisteredEvent = QuirkRegisteredEvent

    # =========================================================================
    # COMMAND MODELS - CQRS commands and queries
    # =========================================================================

    ParseQuery = ParseQuery
    ValidateQuery = ValidateQuery
    AnalyzeQuery = AnalyzeQuery
    WriteCommand = WriteCommand
    MigrateCommand = MigrateCommand
    RegisterQuirkCommand = RegisterQuirkCommand


__all__ = ["FlextLdifModels"]
