# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.result import FlextResult as r
from flext_ldif.__version__ import *
from flext_ldif.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)

if _t.TYPE_CHECKING:
    import flext_ldif._models as _flext_ldif__models

    _models = _flext_ldif__models
    import flext_ldif._models.collections as _flext_ldif__models_collections

    collections = _flext_ldif__models_collections
    import flext_ldif._models.domain as _flext_ldif__models_domain

    domain = _flext_ldif__models_domain
    import flext_ldif._models.domain_entries as _flext_ldif__models_domain_entries

    domain_entries = _flext_ldif__models_domain_entries
    import flext_ldif._models.events as _flext_ldif__models_events

    events = _flext_ldif__models_events
    import flext_ldif._models.metadata as _flext_ldif__models_metadata

    metadata = _flext_ldif__models_metadata
    import flext_ldif._models.processing as _flext_ldif__models_processing

    processing = _flext_ldif__models_processing
    import flext_ldif._models.results as _flext_ldif__models_results

    results = _flext_ldif__models_results
    import flext_ldif._utilities as _flext_ldif__utilities

    _utilities = _flext_ldif__utilities
    import flext_ldif._utilities.acl as _flext_ldif__utilities_acl

    acl = _flext_ldif__utilities_acl
    import flext_ldif._utilities.attribute as _flext_ldif__utilities_attribute

    attribute = _flext_ldif__utilities_attribute
    import flext_ldif._utilities.collection_ldif as _flext_ldif__utilities_collection_ldif

    collection_ldif = _flext_ldif__utilities_collection_ldif
    import flext_ldif._utilities.detection as _flext_ldif__utilities_detection

    detection = _flext_ldif__utilities_detection
    import flext_ldif._utilities.dispatch as _flext_ldif__utilities_dispatch

    dispatch = _flext_ldif__utilities_dispatch
    import flext_ldif._utilities.dn as _flext_ldif__utilities_dn

    dn = _flext_ldif__utilities_dn
    import flext_ldif._utilities.entry as _flext_ldif__utilities_entry

    entry = _flext_ldif__utilities_entry
    import flext_ldif._utilities.object_class as _flext_ldif__utilities_object_class

    object_class = _flext_ldif__utilities_object_class
    import flext_ldif._utilities.oid as _flext_ldif__utilities_oid

    oid = _flext_ldif__utilities_oid
    import flext_ldif._utilities.parser as _flext_ldif__utilities_parser

    parser = _flext_ldif__utilities_parser
    import flext_ldif._utilities.parsers as _flext_ldif__utilities_parsers

    parsers = _flext_ldif__utilities_parsers
    import flext_ldif._utilities.pipeline as _flext_ldif__utilities_pipeline

    pipeline = _flext_ldif__utilities_pipeline
    import flext_ldif._utilities.result as _flext_ldif__utilities_result

    result = _flext_ldif__utilities_result
    import flext_ldif._utilities.schema as _flext_ldif__utilities_schema

    schema = _flext_ldif__utilities_schema
    import flext_ldif._utilities.server as _flext_ldif__utilities_server

    server = _flext_ldif__utilities_server
    import flext_ldif._utilities.transformers as _flext_ldif__utilities_transformers

    transformers = _flext_ldif__utilities_transformers
    import flext_ldif._utilities.validation as _flext_ldif__utilities_validation

    validation = _flext_ldif__utilities_validation
    import flext_ldif._utilities.writer as _flext_ldif__utilities_writer

    writer = _flext_ldif__utilities_writer
    import flext_ldif._utilities.writers as _flext_ldif__utilities_writers

    writers = _flext_ldif__utilities_writers
    import flext_ldif.api as _flext_ldif_api

    api = _flext_ldif_api
    import flext_ldif.base as _flext_ldif_base

    base = _flext_ldif_base
    import flext_ldif.constants as _flext_ldif_constants

    constants = _flext_ldif_constants
    import flext_ldif.models as _flext_ldif_models

    models = _flext_ldif_models
    import flext_ldif.protocols as _flext_ldif_protocols

    protocols = _flext_ldif_protocols
    import flext_ldif.servers as _flext_ldif_servers

    servers = _flext_ldif_servers
    import flext_ldif.servers.ad as _flext_ldif_servers_ad

    ad = _flext_ldif_servers_ad
    import flext_ldif.servers.apache as _flext_ldif_servers_apache

    apache = _flext_ldif_servers_apache
    import flext_ldif.servers.ds389 as _flext_ldif_servers_ds389

    ds389 = _flext_ldif_servers_ds389
    import flext_ldif.servers.novell as _flext_ldif_servers_novell

    novell = _flext_ldif_servers_novell
    import flext_ldif.servers.openldap as _flext_ldif_servers_openldap

    openldap = _flext_ldif_servers_openldap
    import flext_ldif.servers.openldap1 as _flext_ldif_servers_openldap1

    openldap1 = _flext_ldif_servers_openldap1
    import flext_ldif.servers.oud as _flext_ldif_servers_oud

    oud = _flext_ldif_servers_oud
    import flext_ldif.servers.relaxed as _flext_ldif_servers_relaxed

    relaxed = _flext_ldif_servers_relaxed
    import flext_ldif.servers.rfc as _flext_ldif_servers_rfc

    rfc = _flext_ldif_servers_rfc
    import flext_ldif.servers.tivoli as _flext_ldif_servers_tivoli

    tivoli = _flext_ldif_servers_tivoli
    import flext_ldif.services as _flext_ldif_services

    services = _flext_ldif_services
    import flext_ldif.services._services.processing_pipeline_service as _flext_ldif_services__services_processing_pipeline_service

    processing_pipeline_service = (
        _flext_ldif_services__services_processing_pipeline_service
    )
    import flext_ldif.services.analysis as _flext_ldif_services_analysis

    analysis = _flext_ldif_services_analysis
    import flext_ldif.services.categorization as _flext_ldif_services_categorization

    categorization = _flext_ldif_services_categorization
    import flext_ldif.services.conversion as _flext_ldif_services_conversion

    conversion = _flext_ldif_services_conversion
    import flext_ldif.services.detector as _flext_ldif_services_detector

    detector = _flext_ldif_services_detector
    import flext_ldif.services.entries as _flext_ldif_services_entries

    entries = _flext_ldif_services_entries
    import flext_ldif.services.filters as _flext_ldif_services_filters

    filters = _flext_ldif_services_filters
    import flext_ldif.services.migration as _flext_ldif_services_migration

    migration = _flext_ldif_services_migration
    import flext_ldif.services.rfc_validation as _flext_ldif_services_rfc_validation

    rfc_validation = _flext_ldif_services_rfc_validation
    import flext_ldif.services.statistics as _flext_ldif_services_statistics

    statistics = _flext_ldif_services_statistics
    import flext_ldif.settings as _flext_ldif_settings

    settings = _flext_ldif_settings
    import flext_ldif.shared as _flext_ldif_shared

    shared = _flext_ldif_shared
    import flext_ldif.typings as _flext_ldif_typings

    typings = _flext_ldif_typings
    import flext_ldif.utilities as _flext_ldif_utilities

    utilities = _flext_ldif_utilities

    _ = (
        FlextLdif,
        FlextLdifAcl,
        FlextLdifAnalysis,
        FlextLdifCategorization,
        FlextLdifConstants,
        FlextLdifConversion,
        FlextLdifDetector,
        FlextLdifDetectorMixin,
        FlextLdifEntries,
        FlextLdifFilters,
        FlextLdifMigrationPipeline,
        FlextLdifModels,
        FlextLdifModelsBases,
        FlextLdifModelsCollections,
        FlextLdifModelsDomains,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsEvents,
        FlextLdifModelsMetadata,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsSettings,
        FlextLdifParser,
        FlextLdifParserMixin,
        FlextLdifProcessing,
        FlextLdifProcessingPipeline,
        FlextLdifProcessingPipelineService,
        FlextLdifProtocols,
        FlextLdifQuirkMethodsMixin,
        FlextLdifServer,
        FlextLdifServersAd,
        FlextLdifServersApache,
        FlextLdifServersBase,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseEntry,
        FlextLdifServersBaseQuirkHelpers,
        FlextLdifServersBaseSchema,
        FlextLdifServersBaseSchemaAcl,
        FlextLdifServersDs389,
        FlextLdifServersNovell,
        FlextLdifServersOid,
        FlextLdifServersOidAcl,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
        FlextLdifServersOpenldap,
        FlextLdifServersOpenldap1,
        FlextLdifServersOud,
        FlextLdifServersOudAcl,
        FlextLdifServersOudConstants,
        FlextLdifServersOudEntry,
        FlextLdifServersOudSchema,
        FlextLdifServersOudUtilities,
        FlextLdifServersRelaxed,
        FlextLdifServersRfc,
        FlextLdifServersRfcAcl,
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcEntry,
        FlextLdifServersRfcSchema,
        FlextLdifServersTivoli,
        FlextLdifServiceBase,
        FlextLdifSettings,
        FlextLdifShared,
        FlextLdifStatistics,
        FlextLdifTransformer,
        FlextLdifTypes,
        FlextLdifUtilities,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesDetection,
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
        FlextLdifUtilitiesMetadata,
        FlextLdifUtilitiesOID,
        FlextLdifUtilitiesObjectClass,
        FlextLdifUtilitiesParser,
        FlextLdifUtilitiesParsers,
        FlextLdifUtilitiesPipeline,
        FlextLdifUtilitiesResult,
        FlextLdifUtilitiesSchema,
        FlextLdifUtilitiesServer,
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
        FlextLdifUtilitiesValidation,
        FlextLdifUtilitiesWriter,
        FlextLdifUtilitiesWriters,
        FlextLdifValidation,
        FlextLdifWriter,
        FlextLdifWriterMixin,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
        _models,
        _utilities,
        acl,
        ad,
        analysis,
        apache,
        api,
        attribute,
        base,
        c,
        categorization,
        collection_ldif,
        collections,
        constants,
        conversion,
        d,
        detection,
        detector,
        dispatch,
        dn,
        domain,
        domain_entries,
        ds389,
        e,
        entries,
        entry,
        events,
        filters,
        h,
        ldif,
        logger,
        m,
        metadata,
        migration,
        models,
        novell,
        object_class,
        oid,
        openldap,
        openldap1,
        oud,
        p,
        parser,
        parsers,
        pipeline,
        processing,
        processing_pipeline_service,
        protocols,
        r,
        relaxed,
        result,
        results,
        rfc,
        rfc_validation,
        s,
        schema,
        server,
        servers,
        services,
        settings,
        shared,
        statistics,
        t,
        tivoli,
        transformers,
        typings,
        u,
        utilities,
        validation,
        writer,
        writers,
        x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_ldif._models",
        "flext_ldif._utilities",
        "flext_ldif.servers",
        "flext_ldif.services",
    ),
    {
        "FlextLdif": "flext_ldif.api",
        "FlextLdifConstants": "flext_ldif.constants",
        "FlextLdifModels": "flext_ldif.models",
        "FlextLdifProtocols": "flext_ldif.protocols",
        "FlextLdifServiceBase": "flext_ldif.base",
        "FlextLdifSettings": "flext_ldif.settings",
        "FlextLdifShared": "flext_ldif.shared",
        "FlextLdifTypes": "flext_ldif.typings",
        "FlextLdifUtilities": "flext_ldif.utilities",
        "__author__": "flext_ldif.__version__",
        "__author_email__": "flext_ldif.__version__",
        "__description__": "flext_ldif.__version__",
        "__license__": "flext_ldif.__version__",
        "__title__": "flext_ldif.__version__",
        "__url__": "flext_ldif.__version__",
        "__version__": "flext_ldif.__version__",
        "__version_info__": "flext_ldif.__version__",
        "_models": "flext_ldif._models",
        "_utilities": "flext_ldif._utilities",
        "api": "flext_ldif.api",
        "base": "flext_ldif.base",
        "c": ("flext_ldif.constants", "FlextLdifConstants"),
        "constants": "flext_ldif.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldif": "flext_ldif.api",
        "m": ("flext_ldif.models", "FlextLdifModels"),
        "models": "flext_ldif.models",
        "p": ("flext_ldif.protocols", "FlextLdifProtocols"),
        "protocols": "flext_ldif.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_ldif.base", "FlextLdifServiceBase"),
        "servers": "flext_ldif.servers",
        "services": "flext_ldif.services",
        "settings": "flext_ldif.settings",
        "shared": "flext_ldif.shared",
        "t": ("flext_ldif.typings", "FlextLdifTypes"),
        "typings": "flext_ldif.typings",
        "u": ("flext_ldif.utilities", "FlextLdifUtilities"),
        "utilities": "flext_ldif.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

__all__ = [
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifDetectorMixin",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifModelsBases",
    "FlextLdifModelsCollections",
    "FlextLdifModelsDomains",
    "FlextLdifModelsDomainsEntries",
    "FlextLdifModelsEvents",
    "FlextLdifModelsMetadata",
    "FlextLdifModelsProcessing",
    "FlextLdifModelsResults",
    "FlextLdifModelsSettings",
    "FlextLdifParser",
    "FlextLdifParserMixin",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifProcessingPipelineService",
    "FlextLdifProtocols",
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "FlextLdifServersTivoli",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifStatistics",
    "FlextLdifTransformer",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesResult",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "FlextLdifValidation",
    "FlextLdifWriter",
    "FlextLdifWriterMixin",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_models",
    "_utilities",
    "acl",
    "ad",
    "analysis",
    "apache",
    "api",
    "attribute",
    "base",
    "c",
    "categorization",
    "collection_ldif",
    "collections",
    "constants",
    "conversion",
    "d",
    "detection",
    "detector",
    "dispatch",
    "dn",
    "domain",
    "domain_entries",
    "ds389",
    "e",
    "entries",
    "entry",
    "events",
    "filters",
    "h",
    "ldif",
    "logger",
    "m",
    "metadata",
    "migration",
    "models",
    "novell",
    "object_class",
    "oid",
    "openldap",
    "openldap1",
    "oud",
    "p",
    "parser",
    "parsers",
    "pipeline",
    "processing",
    "processing_pipeline_service",
    "protocols",
    "r",
    "relaxed",
    "result",
    "results",
    "rfc",
    "rfc_validation",
    "s",
    "schema",
    "server",
    "servers",
    "services",
    "settings",
    "shared",
    "statistics",
    "t",
    "tivoli",
    "transformers",
    "typings",
    "u",
    "utilities",
    "validation",
    "writer",
    "writers",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
