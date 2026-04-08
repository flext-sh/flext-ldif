# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "AciLineFormatConfig": ("flext_ldif._models.settings", "AciLineFormatConfig"),
    "AciParserConfig": ("flext_ldif._models.settings", "AciParserConfig"),
    "AclMetadataConfig": ("flext_ldif._models.settings", "AclMetadataConfig"),
    "AttrNormalizationConfig": (
        "flext_ldif._models.settings",
        "AttrNormalizationConfig",
    ),
    "BatchWriteConfig": ("flext_ldif._models.settings", "BatchWriteConfig"),
    "CategoryRules": ("flext_ldif._models.settings", "CategoryRules"),
    "DnNormalizationConfig": ("flext_ldif._models.settings", "DnNormalizationConfig"),
    "EntryCriteriaConfig": ("flext_ldif._models.settings", "EntryCriteriaConfig"),
    "EntryParseMetadataConfig": (
        "flext_ldif._models.settings",
        "EntryParseMetadataConfig",
    ),
    "EntryTransformConfig": ("flext_ldif._models.settings", "EntryTransformConfig"),
    "EntryWriteConfig": ("flext_ldif._models.settings", "EntryWriteConfig"),
    "FlextLdifModelsBases": ("flext_ldif._models.base", "FlextLdifModelsBases"),
    "FlextLdifModelsCollections": (
        "flext_ldif._models.collections",
        "FlextLdifModelsCollections",
    ),
    "FlextLdifModelsDomainAcl": (
        "flext_ldif._models.domain_acl",
        "FlextLdifModelsDomainAcl",
    ),
    "FlextLdifModelsDomainAttributes": (
        "flext_ldif._models.domain_attributes",
        "FlextLdifModelsDomainAttributes",
    ),
    "FlextLdifModelsDomainDN": (
        "flext_ldif._models.domain_dn",
        "FlextLdifModelsDomainDN",
    ),
    "FlextLdifModelsDomainEntry": (
        "flext_ldif._models.domain_entry",
        "FlextLdifModelsDomainEntry",
    ),
    "FlextLdifModelsDomainMetadata": (
        "flext_ldif._models.domain_metadata",
        "FlextLdifModelsDomainMetadata",
    ),
    "FlextLdifModelsDomainSchema": (
        "flext_ldif._models.domain_schema",
        "FlextLdifModelsDomainSchema",
    ),
    "FlextLdifModelsDomainsEntries": (
        "flext_ldif._models.domain_entries",
        "FlextLdifModelsDomainsEntries",
    ),
    "FlextLdifModelsEvents": ("flext_ldif._models.events", "FlextLdifModelsEvents"),
    "FlextLdifModelsMetadata": (
        "flext_ldif._models.metadata",
        "FlextLdifModelsMetadata",
    ),
    "FlextLdifModelsProcessing": (
        "flext_ldif._models.processing",
        "FlextLdifModelsProcessing",
    ),
    "FlextLdifModelsResults": ("flext_ldif._models.results", "FlextLdifModelsResults"),
    "FlextLdifModelsSettings": (
        "flext_ldif._models.settings",
        "FlextLdifModelsSettings",
    ),
    "LogContextExtras": ("flext_ldif._models.settings", "LogContextExtras"),
    "MigrateOptions": ("flext_ldif._models.settings", "MigrateOptions"),
    "PermissionMappingConfig": (
        "flext_ldif._models.settings",
        "PermissionMappingConfig",
    ),
    "ProcessConfig": ("flext_ldif._models.settings", "ProcessConfig"),
    "RdnProcessingConfig": ("flext_ldif._models.settings", "RdnProcessingConfig"),
    "SchemaAttributeConversionPipelineConfig": (
        "flext_ldif._models.settings",
        "SchemaAttributeConversionPipelineConfig",
    ),
    "SchemaObjectClassConversionPipelineConfig": (
        "flext_ldif._models.settings",
        "SchemaObjectClassConversionPipelineConfig",
    ),
    "ServerPatternsConfig": ("flext_ldif._models.settings", "ServerPatternsConfig"),
    "ServerValidationRules": ("flext_ldif._models.settings", "ServerValidationRules"),
    "SortConfig": ("flext_ldif._models.settings", "SortConfig"),
    "TransformConfig": ("flext_ldif._models.settings", "TransformConfig"),
    "WhitelistRules": ("flext_ldif._models.settings", "WhitelistRules"),
    "WriteFormatOptions": ("flext_ldif._models.settings", "WriteFormatOptions"),
    "WriteOutputOptions": ("flext_ldif._models.settings", "WriteOutputOptions"),
    "base": "flext_ldif._models.base",
    "collections": "flext_ldif._models.collections",
    "domain_acl": "flext_ldif._models.domain_acl",
    "domain_attributes": "flext_ldif._models.domain_attributes",
    "domain_dn": "flext_ldif._models.domain_dn",
    "domain_entries": "flext_ldif._models.domain_entries",
    "domain_entry": "flext_ldif._models.domain_entry",
    "domain_metadata": "flext_ldif._models.domain_metadata",
    "domain_schema": "flext_ldif._models.domain_schema",
    "events": "flext_ldif._models.events",
    "metadata": "flext_ldif._models.metadata",
    "processing": "flext_ldif._models.processing",
    "results": "flext_ldif._models.results",
    "settings": "flext_ldif._models.settings",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
