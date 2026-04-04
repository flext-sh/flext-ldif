# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._models.base as _flext_ldif__models_base

    base = _flext_ldif__models_base
    import flext_ldif._models.collections as _flext_ldif__models_collections
    from flext_ldif._models.base import FlextLdifModelsBases

    collections = _flext_ldif__models_collections
    import flext_ldif._models.domain_acl as _flext_ldif__models_domain_acl
    from flext_ldif._models.collections import FlextLdifModelsCollections

    domain_acl = _flext_ldif__models_domain_acl
    import flext_ldif._models.domain_attributes as _flext_ldif__models_domain_attributes
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl

    domain_attributes = _flext_ldif__models_domain_attributes
    import flext_ldif._models.domain_dn as _flext_ldif__models_domain_dn
    from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes

    domain_dn = _flext_ldif__models_domain_dn
    import flext_ldif._models.domain_entries as _flext_ldif__models_domain_entries
    from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN

    domain_entries = _flext_ldif__models_domain_entries
    import flext_ldif._models.domain_entry as _flext_ldif__models_domain_entry
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries

    domain_entry = _flext_ldif__models_domain_entry
    import flext_ldif._models.domain_metadata as _flext_ldif__models_domain_metadata
    from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry

    domain_metadata = _flext_ldif__models_domain_metadata
    import flext_ldif._models.domain_schema as _flext_ldif__models_domain_schema
    from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata

    domain_schema = _flext_ldif__models_domain_schema
    import flext_ldif._models.events as _flext_ldif__models_events
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema

    events = _flext_ldif__models_events
    import flext_ldif._models.metadata as _flext_ldif__models_metadata
    from flext_ldif._models.events import FlextLdifModelsEvents

    metadata = _flext_ldif__models_metadata
    import flext_ldif._models.processing as _flext_ldif__models_processing
    from flext_ldif._models.metadata import FlextLdifModelsMetadata

    processing = _flext_ldif__models_processing
    import flext_ldif._models.results as _flext_ldif__models_results
    from flext_ldif._models.processing import FlextLdifModelsProcessing

    results = _flext_ldif__models_results
    import flext_ldif._models.settings as _flext_ldif__models_settings
    from flext_ldif._models.results import FlextLdifModelsResults

    settings = _flext_ldif__models_settings
    from flext_ldif._models.settings import (
        AciLineFormatConfig,
        AciParserConfig,
        AclMetadataConfig,
        AttrNormalizationConfig,
        BatchWriteConfig,
        CategoryRules,
        DnNormalizationConfig,
        EntryCriteriaConfig,
        EntryParseMetadataConfig,
        EntryTransformConfig,
        EntryWriteConfig,
        FlextLdifModelsSettings,
        LogContextExtras,
        MigrateOptions,
        PermissionMappingConfig,
        ProcessConfig,
        RdnProcessingConfig,
        SchemaAttributeConversionPipelineConfig,
        SchemaObjectClassConversionPipelineConfig,
        ServerPatternsConfig,
        ServerValidationRules,
        SortConfig,
        TransformConfig,
        WhitelistRules,
        WriteFormatOptions,
        WriteOutputOptions,
    )
_LAZY_IMPORTS = {
    "AciLineFormatConfig": "flext_ldif._models.settings",
    "AciParserConfig": "flext_ldif._models.settings",
    "AclMetadataConfig": "flext_ldif._models.settings",
    "AttrNormalizationConfig": "flext_ldif._models.settings",
    "BatchWriteConfig": "flext_ldif._models.settings",
    "CategoryRules": "flext_ldif._models.settings",
    "DnNormalizationConfig": "flext_ldif._models.settings",
    "EntryCriteriaConfig": "flext_ldif._models.settings",
    "EntryParseMetadataConfig": "flext_ldif._models.settings",
    "EntryTransformConfig": "flext_ldif._models.settings",
    "EntryWriteConfig": "flext_ldif._models.settings",
    "FlextLdifModelsBases": "flext_ldif._models.base",
    "FlextLdifModelsCollections": "flext_ldif._models.collections",
    "FlextLdifModelsDomainAcl": "flext_ldif._models.domain_acl",
    "FlextLdifModelsDomainAttributes": "flext_ldif._models.domain_attributes",
    "FlextLdifModelsDomainDN": "flext_ldif._models.domain_dn",
    "FlextLdifModelsDomainEntry": "flext_ldif._models.domain_entry",
    "FlextLdifModelsDomainMetadata": "flext_ldif._models.domain_metadata",
    "FlextLdifModelsDomainSchema": "flext_ldif._models.domain_schema",
    "FlextLdifModelsDomainsEntries": "flext_ldif._models.domain_entries",
    "FlextLdifModelsEvents": "flext_ldif._models.events",
    "FlextLdifModelsMetadata": "flext_ldif._models.metadata",
    "FlextLdifModelsProcessing": "flext_ldif._models.processing",
    "FlextLdifModelsResults": "flext_ldif._models.results",
    "FlextLdifModelsSettings": "flext_ldif._models.settings",
    "LogContextExtras": "flext_ldif._models.settings",
    "MigrateOptions": "flext_ldif._models.settings",
    "PermissionMappingConfig": "flext_ldif._models.settings",
    "ProcessConfig": "flext_ldif._models.settings",
    "RdnProcessingConfig": "flext_ldif._models.settings",
    "SchemaAttributeConversionPipelineConfig": "flext_ldif._models.settings",
    "SchemaObjectClassConversionPipelineConfig": "flext_ldif._models.settings",
    "ServerPatternsConfig": "flext_ldif._models.settings",
    "ServerValidationRules": "flext_ldif._models.settings",
    "SortConfig": "flext_ldif._models.settings",
    "TransformConfig": "flext_ldif._models.settings",
    "WhitelistRules": "flext_ldif._models.settings",
    "WriteFormatOptions": "flext_ldif._models.settings",
    "WriteOutputOptions": "flext_ldif._models.settings",
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

__all__ = [
    "AciLineFormatConfig",
    "AciParserConfig",
    "AclMetadataConfig",
    "AttrNormalizationConfig",
    "BatchWriteConfig",
    "CategoryRules",
    "DnNormalizationConfig",
    "EntryCriteriaConfig",
    "EntryParseMetadataConfig",
    "EntryTransformConfig",
    "EntryWriteConfig",
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsDomainAcl",
    "FlextLdifModelsDomainAttributes",
    "FlextLdifModelsDomainDN",
    "FlextLdifModelsDomainEntry",
    "FlextLdifModelsDomainMetadata",
    "FlextLdifModelsDomainSchema",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsMetadata",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsSettings",
    "LogContextExtras",
    "MigrateOptions",
    "PermissionMappingConfig",
    "ProcessConfig",
    "RdnProcessingConfig",
    "SchemaAttributeConversionPipelineConfig",
    "SchemaObjectClassConversionPipelineConfig",
    "ServerPatternsConfig",
    "ServerValidationRules",
    "SortConfig",
    "TransformConfig",
    "WhitelistRules",
    "WriteFormatOptions",
    "WriteOutputOptions",
    "base",
    "collections",
    "domain_acl",
    "domain_attributes",
    "domain_dn",
    "domain_entries",
    "domain_entry",
    "domain_metadata",
    "domain_schema",
    "events",
    "metadata",
    "processing",
    "results",
    "settings",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
