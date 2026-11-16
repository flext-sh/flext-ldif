# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._models.acl_convert import FlextLdifModelsAclConvert
    from flext_ldif._models.base import FlextLdifModelsBases
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.composite import FlextLdifModelsComposite
    from flext_ldif._models.config import FlextLdifModelsConfig
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl
    from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes
    from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry
    from flext_ldif._models.domain_entry_change import (
        FlextLdifModelsDomainEntryChangeOperation,
    )
    from flext_ldif._models.domain_entry_change_value import (
        FlextLdifModelsDomainEntryChangeOperationValue,
    )
    from flext_ldif._models.domain_entry_control import (
        FlextLdifModelsDomainEntryControl,
    )
    from flext_ldif._models.domain_entry_statistics import (
        FlextLdifModelsDomainEntryStatistics,
    )
    from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema
    from flext_ldif._models.elements import FlextLdifModelsBasesParts
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.results_statistics import FlextLdifModelsResultsStatistics
    from flext_ldif._models.settings import FlextLdifModelsSettings


__all__: tuple[str, ...] = (
    "FlextLdifModelsAclConvert",
    "FlextLdifModelsBases",
    "FlextLdifModelsBasesParts",
    "FlextLdifModelsCollections",
    "FlextLdifModelsComposite",
    "FlextLdifModelsConfig",
    "FlextLdifModelsDomainAcl",
    "FlextLdifModelsDomainAttributes",
    "FlextLdifModelsDomainDN",
    "FlextLdifModelsDomainEntry",
    "FlextLdifModelsDomainEntryChangeOperation",
    "FlextLdifModelsDomainEntryChangeOperationValue",
    "FlextLdifModelsDomainEntryControl",
    "FlextLdifModelsDomainEntryStatistics",
    "FlextLdifModelsDomainMetadata",
    "FlextLdifModelsDomainSchema",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsResultsStatistics",
    "FlextLdifModelsSettings",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifModelsAclConvert": ".acl_convert",
        "FlextLdifModelsBases": ".base",
        "FlextLdifModelsBasesParts": ".elements",
        "FlextLdifModelsCollections": ".collections",
        "FlextLdifModelsComposite": ".composite",
        "FlextLdifModelsConfig": ".config",
        "FlextLdifModelsDomainAcl": ".domain_acl",
        "FlextLdifModelsDomainAttributes": ".domain_attributes",
        "FlextLdifModelsDomainDN": ".domain_dn",
        "FlextLdifModelsDomainEntry": ".domain_entry",
        "FlextLdifModelsDomainEntryChangeOperation": ".domain_entry_change",
        "FlextLdifModelsDomainEntryChangeOperationValue": ".domain_entry_change_value",
        "FlextLdifModelsDomainEntryControl": ".domain_entry_control",
        "FlextLdifModelsDomainEntryStatistics": ".domain_entry_statistics",
        "FlextLdifModelsDomainMetadata": ".domain_metadata",
        "FlextLdifModelsDomainSchema": ".domain_schema",
        "FlextLdifModelsDomainsEntries": ".domain_entries",
        "FlextLdifModelsEvents": ".events",
        "FlextLdifModelsProcessing": ".processing",
        "FlextLdifModelsResults": ".results",
        "FlextLdifModelsResultsStatistics": ".results_statistics",
        "FlextLdifModelsSettings": ".settings",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifModelsAclConvert": (
            "OidAclSubject",
            "OidAclRule",
            "AclPermissionResolution",
            "AclSecurityGroup",
            "AclDirectory",
            "AclBindLeaf",
            "AclBindRule",
            "AclAttrSet",
            "AclClause",
            "AclLevelRule",
            "AclResolution",
            "AclForm",
            "AclDecision",
            "AclRegion",
            "AclNearerGrant",
            "AciStatement",
            "AclConversionEvent",
            "AclDirectoryConversion",
            "AclEntryConversion",
            "AclSubjectMatcher",
            "AclSubjectMatcherCatalog",
            "OidAclSubjectModifiers",
        ),
        "FlextLdifModelsBases": ("RegistryPortOptions",),
        "FlextLdifModelsBasesParts": (
            "SchemaElement",
            "AclElement",
        ),
        "FlextLdifModelsCollections": (
            "DynamicCounts",
            "SchemaContent",
            "FlexibleCategories",
        ),
        "FlextLdifModelsComposite": (
            "Stats",
            "OidAclMetadataConfig",
        ),
        "FlextLdifModelsConfig": ("ConfigNamespace",),
        "FlextLdifModelsDomainAcl": (
            "AclPermissions",
            "AclTarget",
            "AclSubject",
            "Acl",
            "AclWriteMetadata",
            "PermissionMappingConfig",
        ),
        "FlextLdifModelsDomainAttributes": (
            "Attributes",
            "AttributeTransformation",
        ),
        "FlextLdifModelsDomainDN": (
            "DNStatistics",
            "DN",
            "DnRegistry",
        ),
        "FlextLdifModelsDomainEntry": ("Entry",),
        "FlextLdifModelsDomainEntryChangeOperation": ("ChangeOperation",),
        "FlextLdifModelsDomainEntryChangeOperationValue": ("ChangeOperationValue",),
        "FlextLdifModelsDomainEntryControl": ("Control",),
        "FlextLdifModelsDomainEntryStatistics": (
            "EntryStatisticsLifecycle",
            "EntryStatisticsChanges",
            "EntryStatisticsOutcome",
            "EntryStatistics",
        ),
        "FlextLdifModelsDomainMetadata": (
            "CommentedAttributeValues",
            "ValidationMetadata",
            "WriteOptions",
            "FormatDetails",
            "SchemaFormatDetails",
            "ServerMetadata",
        ),
        "FlextLdifModelsDomainSchema": (
            "SchemaAttribute",
            "Syntax",
            "SchemaObjectClass",
        ),
        "FlextLdifModelsDomainsEntries": (),
        "FlextLdifModelsEvents": (
            "DnEventConfig",
            "ConversionEventConfig",
            "DnEvent",
            "ConversionEvent",
        ),
        "FlextLdifModelsProcessing": (
            "ProcessingPipelineOptions",
            "ProcessingResult",
            "ProcessEntriesOptions",
        ),
        "FlextLdifModelsResults": (
            "WriteRequest",
            "MigrationPipelineOptions",
            "MigrationSummary",
            "MigrationPipelineResult",
            "ValidationResult",
            "ServerDetectionResult",
            "EntriesStatistics",
            "Response",
            "ParseResponse",
            "AclResponse",
            "AclEvaluationResult",
            "WriteResponse",
        ),
        "FlextLdifModelsResultsStatistics": (
            "StatisticsSummary",
            "StatisticsEntryCounts",
            "StatisticsSchemaAcl",
            "StatisticsRun",
            "Statistics",
        ),
        "FlextLdifModelsSettings": (),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextLdifModelsBases": ((".", "FlextLdifModelsBasesParts"),),
        "FlextLdifModelsDomainEntry": (
            (".", "FlextLdifModelsDomainEntryChangeOperation"),
        ),
        "FlextLdifModelsDomainsEntries": (
            (".", "FlextLdifModelsDomainEntry"),
            (".", "FlextLdifModelsDomainMetadata"),
            (".", "FlextLdifModelsAclConvert"),
            (".", "FlextLdifModelsDomainAcl"),
            (".", "FlextLdifModelsDomainAttributes"),
            (".", "FlextLdifModelsDomainSchema"),
            (".", "FlextLdifModelsDomainDN"),
        ),
        "FlextLdifModelsResults": ((".", "FlextLdifModelsResultsStatistics"),),
        "FlextLdifModelsSettings": (
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsAcl"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsCriteria"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsMigrate"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsMisc"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsNormalization"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsProcessing"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsRules"),
            ("flext_ldif._models._settings", "FlextLdifModelsSettingsValidation"),
        ),
    },
)
