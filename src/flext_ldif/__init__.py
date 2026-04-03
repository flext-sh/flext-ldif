# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_ldif.__version__ import *

if _t.TYPE_CHECKING:
    import flext_ldif._models as _flext_ldif__models
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

    _models = _flext_ldif__models
    import flext_ldif._models.collections as _flext_ldif__models_collections
    from flext_ldif._models.base import FlextLdifModelsBases

    collections = _flext_ldif__models_collections
    import flext_ldif._models.domain as _flext_ldif__models_domain
    from flext_ldif._models.collections import FlextLdifModelsCollections

    domain = _flext_ldif__models_domain
    import flext_ldif._models.domain_entries as _flext_ldif__models_domain_entries
    from flext_ldif._models.domain import FlextLdifModelsDomains

    domain_entries = _flext_ldif__models_domain_entries
    import flext_ldif._models.events as _flext_ldif__models_events
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries

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
    import flext_ldif._utilities as _flext_ldif__utilities
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings

    _utilities = _flext_ldif__utilities
    import flext_ldif._utilities.acl as _flext_ldif__utilities_acl

    acl = _flext_ldif__utilities_acl
    import flext_ldif._utilities.attribute as _flext_ldif__utilities_attribute
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL

    attribute = _flext_ldif__utilities_attribute
    import flext_ldif._utilities.collection_ldif as _flext_ldif__utilities_collection_ldif
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute

    collection_ldif = _flext_ldif__utilities_collection_ldif
    import flext_ldif._utilities.detection as _flext_ldif__utilities_detection
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif

    detection = _flext_ldif__utilities_detection
    import flext_ldif._utilities.dispatch as _flext_ldif__utilities_dispatch
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection

    dispatch = _flext_ldif__utilities_dispatch
    import flext_ldif._utilities.dn as _flext_ldif__utilities_dn
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch

    dn = _flext_ldif__utilities_dn
    import flext_ldif._utilities.entry as _flext_ldif__utilities_entry
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN

    entry = _flext_ldif__utilities_entry
    import flext_ldif._utilities.object_class as _flext_ldif__utilities_object_class
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata

    object_class = _flext_ldif__utilities_object_class
    import flext_ldif._utilities.oid as _flext_ldif__utilities_oid
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass

    oid = _flext_ldif__utilities_oid
    import flext_ldif._utilities.parser as _flext_ldif__utilities_parser
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID

    parser = _flext_ldif__utilities_parser
    import flext_ldif._utilities.parsers as _flext_ldif__utilities_parsers
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser

    parsers = _flext_ldif__utilities_parsers
    import flext_ldif._utilities.pipeline as _flext_ldif__utilities_pipeline
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers

    pipeline = _flext_ldif__utilities_pipeline
    import flext_ldif._utilities.result as _flext_ldif__utilities_result
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline

    result = _flext_ldif__utilities_result
    import flext_ldif._utilities.schema as _flext_ldif__utilities_schema
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult

    schema = _flext_ldif__utilities_schema
    import flext_ldif._utilities.server as _flext_ldif__utilities_server
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema

    server = _flext_ldif__utilities_server
    import flext_ldif._utilities.transformers as _flext_ldif__utilities_transformers
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer

    transformers = _flext_ldif__utilities_transformers
    import flext_ldif._utilities.validation as _flext_ldif__utilities_validation
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )

    validation = _flext_ldif__utilities_validation
    import flext_ldif._utilities.writer as _flext_ldif__utilities_writer
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation

    writer = _flext_ldif__utilities_writer
    import flext_ldif._utilities.writers as _flext_ldif__utilities_writers
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter

    writers = _flext_ldif__utilities_writers
    import flext_ldif.api as _flext_ldif_api
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters

    api = _flext_ldif_api
    import flext_ldif.base as _flext_ldif_base
    from flext_ldif.api import FlextLdif, ldif

    base = _flext_ldif_base
    import flext_ldif.constants as _flext_ldif_constants
    from flext_ldif.base import FlextLdifServiceBase, FlextLdifServiceBase as s

    constants = _flext_ldif_constants
    import flext_ldif.models as _flext_ldif_models
    from flext_ldif.constants import FlextLdifConstants, FlextLdifConstants as c

    models = _flext_ldif_models
    import flext_ldif.protocols as _flext_ldif_protocols
    from flext_ldif.models import FlextLdifModels, FlextLdifModels as m

    protocols = _flext_ldif_protocols
    import flext_ldif.servers as _flext_ldif_servers
    from flext_ldif.protocols import FlextLdifProtocols, FlextLdifProtocols as p

    servers = _flext_ldif_servers
    import flext_ldif.servers.ad as _flext_ldif_servers_ad
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import (
        FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers,
    )
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema

    ad = _flext_ldif_servers_ad
    import flext_ldif.servers.apache as _flext_ldif_servers_apache
    from flext_ldif.servers.ad import FlextLdifServersAd

    apache = _flext_ldif_servers_apache
    import flext_ldif.servers.ds389 as _flext_ldif_servers_ds389
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase

    ds389 = _flext_ldif_servers_ds389
    import flext_ldif.servers.novell as _flext_ldif_servers_novell
    from flext_ldif.servers.ds389 import FlextLdifServersDs389

    novell = _flext_ldif_servers_novell
    import flext_ldif.servers.openldap as _flext_ldif_servers_openldap
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid, logger

    openldap = _flext_ldif_servers_openldap
    import flext_ldif.servers.openldap1 as _flext_ldif_servers_openldap1
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap

    openldap1 = _flext_ldif_servers_openldap1
    import flext_ldif.servers.oud as _flext_ldif_servers_oud
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1

    oud = _flext_ldif_servers_oud
    import flext_ldif.servers.relaxed as _flext_ldif_servers_relaxed
    from flext_ldif.servers.oud import FlextLdifServersOud

    relaxed = _flext_ldif_servers_relaxed
    import flext_ldif.servers.rfc as _flext_ldif_servers_rfc
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed

    rfc = _flext_ldif_servers_rfc
    import flext_ldif.servers.tivoli as _flext_ldif_servers_tivoli
    from flext_ldif.servers.rfc import FlextLdifServersRfc

    tivoli = _flext_ldif_servers_tivoli
    import flext_ldif.services as _flext_ldif_services
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli

    services = _flext_ldif_services
    import flext_ldif.services._services.processing_pipeline_service as _flext_ldif_services__services_processing_pipeline_service

    processing_pipeline_service = (
        _flext_ldif_services__services_processing_pipeline_service
    )
    import flext_ldif.services.analysis as _flext_ldif_services_analysis
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
    )
    from flext_ldif.services.acl import FlextLdifAcl

    analysis = _flext_ldif_services_analysis
    import flext_ldif.services.categorization as _flext_ldif_services_categorization
    from flext_ldif.services.analysis import FlextLdifAnalysis

    categorization = _flext_ldif_services_categorization
    import flext_ldif.services.conversion as _flext_ldif_services_conversion
    from flext_ldif.services.categorization import FlextLdifCategorization

    conversion = _flext_ldif_services_conversion
    import flext_ldif.services.detector as _flext_ldif_services_detector
    from flext_ldif.services.conversion import FlextLdifConversion

    detector = _flext_ldif_services_detector
    import flext_ldif.services.entries as _flext_ldif_services_entries
    from flext_ldif.services.detector import FlextLdifDetector, FlextLdifDetectorMixin

    entries = _flext_ldif_services_entries
    import flext_ldif.services.filters as _flext_ldif_services_filters
    from flext_ldif.services.entries import FlextLdifEntries

    filters = _flext_ldif_services_filters
    import flext_ldif.services.migration as _flext_ldif_services_migration
    from flext_ldif.services.filters import FlextLdifFilters

    migration = _flext_ldif_services_migration
    import flext_ldif.services.rfc_validation as _flext_ldif_services_rfc_validation
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser, FlextLdifParserMixin
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing

    rfc_validation = _flext_ldif_services_rfc_validation
    import flext_ldif.services.statistics as _flext_ldif_services_statistics
    from flext_ldif.services.rfc_validation import FlextLdifValidation
    from flext_ldif.services.server import FlextLdifServer

    statistics = _flext_ldif_services_statistics
    import flext_ldif.settings as _flext_ldif_settings
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.writer import FlextLdifWriter, FlextLdifWriterMixin

    settings = _flext_ldif_settings
    import flext_ldif.shared as _flext_ldif_shared
    from flext_ldif.settings import FlextLdifSettings

    shared = _flext_ldif_shared
    import flext_ldif.typings as _flext_ldif_typings
    from flext_ldif.shared import FlextLdifShared

    typings = _flext_ldif_typings
    import flext_ldif.utilities as _flext_ldif_utilities
    from flext_ldif.typings import FlextLdifTypes, FlextLdifTypes as t

    utilities = _flext_ldif_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_ldif.utilities import FlextLdifUtilities, FlextLdifUtilities as u
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
