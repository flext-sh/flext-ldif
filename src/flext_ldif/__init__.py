# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from flext_ldif.__version__ import (
    __author__ as __author__,
    __author_email__ as __author_email__,
    __description__ as __description__,
    __license__ as __license__,
    __title__ as __title__,
    __url__ as __url__,
    __version__ as __version__,
    __version_info__ as __version_info__,
)

if TYPE_CHECKING:
    from flext_ldif import (
        _models as _models,
        _utilities as _utilities,
        api as api,
        base as base,
        constants as constants,
        models as models,
        protocols as protocols,
        servers as servers,
        services as services,
        settings as settings,
        shared as shared,
        typings as typings,
        utilities as utilities,
    )
    from flext_ldif._models import (
        collections as collections,
        domain as domain,
        domain_entries as domain_entries,
        events as events,
        metadata as metadata,
        processing as processing,
        results as results,
    )
    from flext_ldif._models.base import FlextLdifModelsBases as FlextLdifModelsBases
    from flext_ldif._models.collections import (
        FlextLdifModelsCollections as FlextLdifModelsCollections,
    )
    from flext_ldif._models.domain import (
        FlextLdifModelsDomains as FlextLdifModelsDomains,
    )
    from flext_ldif._models.domain_entries import (
        FlextLdifModelsDomainsEntries as FlextLdifModelsDomainsEntries,
    )
    from flext_ldif._models.events import FlextLdifModelsEvents as FlextLdifModelsEvents
    from flext_ldif._models.metadata import (
        FlextLdifModelsMetadata as FlextLdifModelsMetadata,
    )
    from flext_ldif._models.processing import (
        FlextLdifModelsProcessing as FlextLdifModelsProcessing,
    )
    from flext_ldif._models.results import (
        FlextLdifModelsResults as FlextLdifModelsResults,
    )
    from flext_ldif._models.settings import (
        FlextLdifModelsSettings as FlextLdifModelsSettings,
    )
    from flext_ldif._utilities import (
        acl as acl,
        attribute as attribute,
        collection_ldif as collection_ldif,
        detection as detection,
        dispatch as dispatch,
        dn as dn,
        entry as entry,
        object_class as object_class,
        oid as oid,
        parser as parser,
        parsers as parsers,
        pipeline as pipeline,
        result as result,
        schema as schema,
        server as server,
        transformers as transformers,
        validation as validation,
        writer as writer,
        writers as writers,
    )
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL as FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import (
        FlextLdifUtilitiesAttribute as FlextLdifUtilitiesAttribute,
    )
    from flext_ldif._utilities.collection_ldif import (
        FlextLdifUtilitiesCollectionLdif as FlextLdifUtilitiesCollectionLdif,
    )
    from flext_ldif._utilities.detection import (
        FlextLdifUtilitiesDetection as FlextLdifUtilitiesDetection,
    )
    from flext_ldif._utilities.dispatch import (
        FlextLdifUtilitiesDispatch as FlextLdifUtilitiesDispatch,
    )
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN as FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import (
        FlextLdifUtilitiesEntry as FlextLdifUtilitiesEntry,
    )
    from flext_ldif._utilities.events import (
        FlextLdifUtilitiesEvents as FlextLdifUtilitiesEvents,
    )
    from flext_ldif._utilities.metadata import (
        FlextLdifUtilitiesMetadata as FlextLdifUtilitiesMetadata,
    )
    from flext_ldif._utilities.object_class import (
        FlextLdifUtilitiesObjectClass as FlextLdifUtilitiesObjectClass,
    )
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID as FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import (
        FlextLdifUtilitiesParser as FlextLdifUtilitiesParser,
    )
    from flext_ldif._utilities.parsers import (
        FlextLdifUtilitiesParsers as FlextLdifUtilitiesParsers,
    )
    from flext_ldif._utilities.pipeline import (
        FlextLdifUtilitiesPipeline as FlextLdifUtilitiesPipeline,
    )
    from flext_ldif._utilities.result import (
        FlextLdifUtilitiesResult as FlextLdifUtilitiesResult,
    )
    from flext_ldif._utilities.schema import (
        FlextLdifUtilitiesSchema as FlextLdifUtilitiesSchema,
    )
    from flext_ldif._utilities.server import (
        FlextLdifUtilitiesServer as FlextLdifUtilitiesServer,
    )
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer as FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers as FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import (
        FlextLdifUtilitiesValidation as FlextLdifUtilitiesValidation,
    )
    from flext_ldif._utilities.writer import (
        FlextLdifUtilitiesWriter as FlextLdifUtilitiesWriter,
    )
    from flext_ldif._utilities.writers import (
        FlextLdifUtilitiesWriters as FlextLdifUtilitiesWriters,
    )
    from flext_ldif.api import FlextLdif as FlextLdif, ldif as ldif
    from flext_ldif.base import FlextLdifServiceBase as FlextLdifServiceBase, s as s
    from flext_ldif.constants import (
        FlextLdifConstants as FlextLdifConstants,
        FlextLdifConstants as c,
    )
    from flext_ldif.models import (
        FlextLdifModels as FlextLdifModels,
        FlextLdifModels as m,
    )
    from flext_ldif.protocols import (
        FlextLdifProtocols as FlextLdifProtocols,
        FlextLdifProtocols as p,
    )
    from flext_ldif.servers import (
        ad as ad,
        apache as apache,
        ds389 as ds389,
        novell as novell,
        openldap as openldap,
        openldap1 as openldap1,
        oud as oud,
        relaxed as relaxed,
        rfc as rfc,
        tivoli as tivoli,
    )
    from flext_ldif.servers._base.acl import (
        FlextLdifServersBaseSchemaAcl as FlextLdifServersBaseSchemaAcl,
    )
    from flext_ldif.servers._base.constants import (
        FlextLdifQuirkMethodsMixin as FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants as FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers as FlextLdifServersBaseQuirkHelpers,
    )
    from flext_ldif.servers._base.entry import (
        FlextLdifServersBaseEntry as FlextLdifServersBaseEntry,
    )
    from flext_ldif.servers._base.schema import (
        FlextLdifServersBaseSchema as FlextLdifServersBaseSchema,
    )
    from flext_ldif.servers._oid.acl import (
        FlextLdifServersOidAcl as FlextLdifServersOidAcl,
    )
    from flext_ldif.servers._oid.constants import (
        FlextLdifServersOidConstants as FlextLdifServersOidConstants,
    )
    from flext_ldif.servers._oid.entry import (
        FlextLdifServersOidEntry as FlextLdifServersOidEntry,
    )
    from flext_ldif.servers._oid.schema import (
        FlextLdifServersOidSchema as FlextLdifServersOidSchema,
    )
    from flext_ldif.servers._oud.acl import (
        FlextLdifServersOudAcl as FlextLdifServersOudAcl,
    )
    from flext_ldif.servers._oud.constants import (
        FlextLdifServersOudConstants as FlextLdifServersOudConstants,
    )
    from flext_ldif.servers._oud.entry import (
        FlextLdifServersOudEntry as FlextLdifServersOudEntry,
    )
    from flext_ldif.servers._oud.schema import (
        FlextLdifServersOudSchema as FlextLdifServersOudSchema,
    )
    from flext_ldif.servers._oud.utilities import (
        FlextLdifServersOudUtilities as FlextLdifServersOudUtilities,
    )
    from flext_ldif.servers._rfc.acl import (
        FlextLdifServersRfcAcl as FlextLdifServersRfcAcl,
    )
    from flext_ldif.servers._rfc.constants import (
        FlextLdifServersRfcConstants as FlextLdifServersRfcConstants,
    )
    from flext_ldif.servers._rfc.entry import (
        FlextLdifServersRfcEntry as FlextLdifServersRfcEntry,
    )
    from flext_ldif.servers._rfc.schema import (
        FlextLdifServersRfcSchema as FlextLdifServersRfcSchema,
    )
    from flext_ldif.servers.ad import FlextLdifServersAd as FlextLdifServersAd
    from flext_ldif.servers.apache import (
        FlextLdifServersApache as FlextLdifServersApache,
    )
    from flext_ldif.servers.base import FlextLdifServersBase as FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389 as FlextLdifServersDs389
    from flext_ldif.servers.novell import (
        FlextLdifServersNovell as FlextLdifServersNovell,
    )
    from flext_ldif.servers.oid import (
        FlextLdifServersOid as FlextLdifServersOid,
        logger as logger,
    )
    from flext_ldif.servers.openldap import (
        FlextLdifServersOpenldap as FlextLdifServersOpenldap,
    )
    from flext_ldif.servers.openldap1 import (
        FlextLdifServersOpenldap1 as FlextLdifServersOpenldap1,
    )
    from flext_ldif.servers.oud import FlextLdifServersOud as FlextLdifServersOud
    from flext_ldif.servers.relaxed import (
        FlextLdifServersRelaxed as FlextLdifServersRelaxed,
    )
    from flext_ldif.servers.rfc import FlextLdifServersRfc as FlextLdifServersRfc
    from flext_ldif.servers.tivoli import (
        FlextLdifServersTivoli as FlextLdifServersTivoli,
    )
    from flext_ldif.services import (
        analysis as analysis,
        categorization as categorization,
        conversion as conversion,
        detector as detector,
        entries as entries,
        filters as filters,
        migration as migration,
        rfc_validation as rfc_validation,
        statistics as statistics,
    )
    from flext_ldif.services._services import (
        processing_pipeline_service as processing_pipeline_service,
    )
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService as FlextLdifProcessingPipelineService,
    )
    from flext_ldif.services.acl import FlextLdifAcl as FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis as FlextLdifAnalysis
    from flext_ldif.services.categorization import (
        FlextLdifCategorization as FlextLdifCategorization,
    )
    from flext_ldif.services.conversion import (
        FlextLdifConversion as FlextLdifConversion,
    )
    from flext_ldif.services.detector import (
        FlextLdifDetector as FlextLdifDetector,
        FlextLdifDetectorMixin as FlextLdifDetectorMixin,
    )
    from flext_ldif.services.entries import FlextLdifEntries as FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters as FlextLdifFilters
    from flext_ldif.services.migration import (
        FlextLdifMigrationPipeline as FlextLdifMigrationPipeline,
    )
    from flext_ldif.services.parser import (
        FlextLdifParser as FlextLdifParser,
        FlextLdifParserMixin as FlextLdifParserMixin,
    )
    from flext_ldif.services.pipeline import (
        FlextLdifProcessingPipeline as FlextLdifProcessingPipeline,
    )
    from flext_ldif.services.processing import (
        FlextLdifProcessing as FlextLdifProcessing,
    )
    from flext_ldif.services.rfc_validation import (
        FlextLdifValidation as FlextLdifValidation,
    )
    from flext_ldif.services.server import FlextLdifServer as FlextLdifServer
    from flext_ldif.services.statistics import (
        FlextLdifStatistics as FlextLdifStatistics,
    )
    from flext_ldif.services.transformers import (
        FlextLdifTransformer as FlextLdifTransformer,
    )
    from flext_ldif.services.writer import (
        FlextLdifWriter as FlextLdifWriter,
        FlextLdifWriterMixin as FlextLdifWriterMixin,
    )
    from flext_ldif.settings import FlextLdifSettings as FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared as FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes as FlextLdifTypes, FlextLdifTypes as t
    from flext_ldif.utilities import (
        FlextLdifUtilities as FlextLdifUtilities,
        FlextLdifUtilities as u,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdif": ["flext_ldif.api", "FlextLdif"],
    "FlextLdifAcl": ["flext_ldif.services.acl", "FlextLdifAcl"],
    "FlextLdifAnalysis": ["flext_ldif.services.analysis", "FlextLdifAnalysis"],
    "FlextLdifCategorization": [
        "flext_ldif.services.categorization",
        "FlextLdifCategorization",
    ],
    "FlextLdifConstants": ["flext_ldif.constants", "FlextLdifConstants"],
    "FlextLdifConversion": ["flext_ldif.services.conversion", "FlextLdifConversion"],
    "FlextLdifDetector": ["flext_ldif.services.detector", "FlextLdifDetector"],
    "FlextLdifDetectorMixin": [
        "flext_ldif.services.detector",
        "FlextLdifDetectorMixin",
    ],
    "FlextLdifEntries": ["flext_ldif.services.entries", "FlextLdifEntries"],
    "FlextLdifFilters": ["flext_ldif.services.filters", "FlextLdifFilters"],
    "FlextLdifMigrationPipeline": [
        "flext_ldif.services.migration",
        "FlextLdifMigrationPipeline",
    ],
    "FlextLdifModels": ["flext_ldif.models", "FlextLdifModels"],
    "FlextLdifModelsBases": ["flext_ldif._models.base", "FlextLdifModelsBases"],
    "FlextLdifModelsCollections": [
        "flext_ldif._models.collections",
        "FlextLdifModelsCollections",
    ],
    "FlextLdifModelsDomains": ["flext_ldif._models.domain", "FlextLdifModelsDomains"],
    "FlextLdifModelsDomainsEntries": [
        "flext_ldif._models.domain_entries",
        "FlextLdifModelsDomainsEntries",
    ],
    "FlextLdifModelsEvents": ["flext_ldif._models.events", "FlextLdifModelsEvents"],
    "FlextLdifModelsMetadata": [
        "flext_ldif._models.metadata",
        "FlextLdifModelsMetadata",
    ],
    "FlextLdifModelsProcessing": [
        "flext_ldif._models.processing",
        "FlextLdifModelsProcessing",
    ],
    "FlextLdifModelsResults": ["flext_ldif._models.results", "FlextLdifModelsResults"],
    "FlextLdifModelsSettings": [
        "flext_ldif._models.settings",
        "FlextLdifModelsSettings",
    ],
    "FlextLdifParser": ["flext_ldif.services.parser", "FlextLdifParser"],
    "FlextLdifParserMixin": ["flext_ldif.services.parser", "FlextLdifParserMixin"],
    "FlextLdifProcessing": ["flext_ldif.services.processing", "FlextLdifProcessing"],
    "FlextLdifProcessingPipeline": [
        "flext_ldif.services.pipeline",
        "FlextLdifProcessingPipeline",
    ],
    "FlextLdifProcessingPipelineService": [
        "flext_ldif.services._services.processing_pipeline_service",
        "FlextLdifProcessingPipelineService",
    ],
    "FlextLdifProtocols": ["flext_ldif.protocols", "FlextLdifProtocols"],
    "FlextLdifQuirkMethodsMixin": [
        "flext_ldif.servers._base.constants",
        "FlextLdifQuirkMethodsMixin",
    ],
    "FlextLdifServer": ["flext_ldif.services.server", "FlextLdifServer"],
    "FlextLdifServersAd": ["flext_ldif.servers.ad", "FlextLdifServersAd"],
    "FlextLdifServersApache": ["flext_ldif.servers.apache", "FlextLdifServersApache"],
    "FlextLdifServersBase": ["flext_ldif.servers.base", "FlextLdifServersBase"],
    "FlextLdifServersBaseConstants": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseConstants",
    ],
    "FlextLdifServersBaseEntry": [
        "flext_ldif.servers._base.entry",
        "FlextLdifServersBaseEntry",
    ],
    "FlextLdifServersBaseQuirkHelpers": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseQuirkHelpers",
    ],
    "FlextLdifServersBaseSchema": [
        "flext_ldif.servers._base.schema",
        "FlextLdifServersBaseSchema",
    ],
    "FlextLdifServersBaseSchemaAcl": [
        "flext_ldif.servers._base.acl",
        "FlextLdifServersBaseSchemaAcl",
    ],
    "FlextLdifServersDs389": ["flext_ldif.servers.ds389", "FlextLdifServersDs389"],
    "FlextLdifServersNovell": ["flext_ldif.servers.novell", "FlextLdifServersNovell"],
    "FlextLdifServersOid": ["flext_ldif.servers.oid", "FlextLdifServersOid"],
    "FlextLdifServersOidAcl": ["flext_ldif.servers._oid.acl", "FlextLdifServersOidAcl"],
    "FlextLdifServersOidConstants": [
        "flext_ldif.servers._oid.constants",
        "FlextLdifServersOidConstants",
    ],
    "FlextLdifServersOidEntry": [
        "flext_ldif.servers._oid.entry",
        "FlextLdifServersOidEntry",
    ],
    "FlextLdifServersOidSchema": [
        "flext_ldif.servers._oid.schema",
        "FlextLdifServersOidSchema",
    ],
    "FlextLdifServersOpenldap": [
        "flext_ldif.servers.openldap",
        "FlextLdifServersOpenldap",
    ],
    "FlextLdifServersOpenldap1": [
        "flext_ldif.servers.openldap1",
        "FlextLdifServersOpenldap1",
    ],
    "FlextLdifServersOud": ["flext_ldif.servers.oud", "FlextLdifServersOud"],
    "FlextLdifServersOudAcl": ["flext_ldif.servers._oud.acl", "FlextLdifServersOudAcl"],
    "FlextLdifServersOudConstants": [
        "flext_ldif.servers._oud.constants",
        "FlextLdifServersOudConstants",
    ],
    "FlextLdifServersOudEntry": [
        "flext_ldif.servers._oud.entry",
        "FlextLdifServersOudEntry",
    ],
    "FlextLdifServersOudSchema": [
        "flext_ldif.servers._oud.schema",
        "FlextLdifServersOudSchema",
    ],
    "FlextLdifServersOudUtilities": [
        "flext_ldif.servers._oud.utilities",
        "FlextLdifServersOudUtilities",
    ],
    "FlextLdifServersRelaxed": [
        "flext_ldif.servers.relaxed",
        "FlextLdifServersRelaxed",
    ],
    "FlextLdifServersRfc": ["flext_ldif.servers.rfc", "FlextLdifServersRfc"],
    "FlextLdifServersRfcAcl": ["flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"],
    "FlextLdifServersRfcConstants": [
        "flext_ldif.servers._rfc.constants",
        "FlextLdifServersRfcConstants",
    ],
    "FlextLdifServersRfcEntry": [
        "flext_ldif.servers._rfc.entry",
        "FlextLdifServersRfcEntry",
    ],
    "FlextLdifServersRfcSchema": [
        "flext_ldif.servers._rfc.schema",
        "FlextLdifServersRfcSchema",
    ],
    "FlextLdifServersTivoli": ["flext_ldif.servers.tivoli", "FlextLdifServersTivoli"],
    "FlextLdifServiceBase": ["flext_ldif.base", "FlextLdifServiceBase"],
    "FlextLdifSettings": ["flext_ldif.settings", "FlextLdifSettings"],
    "FlextLdifShared": ["flext_ldif.shared", "FlextLdifShared"],
    "FlextLdifStatistics": ["flext_ldif.services.statistics", "FlextLdifStatistics"],
    "FlextLdifTransformer": [
        "flext_ldif.services.transformers",
        "FlextLdifTransformer",
    ],
    "FlextLdifTypes": ["flext_ldif.typings", "FlextLdifTypes"],
    "FlextLdifUtilities": ["flext_ldif.utilities", "FlextLdifUtilities"],
    "FlextLdifUtilitiesACL": ["flext_ldif._utilities.acl", "FlextLdifUtilitiesACL"],
    "FlextLdifUtilitiesAttribute": [
        "flext_ldif._utilities.attribute",
        "FlextLdifUtilitiesAttribute",
    ],
    "FlextLdifUtilitiesCollectionLdif": [
        "flext_ldif._utilities.collection_ldif",
        "FlextLdifUtilitiesCollectionLdif",
    ],
    "FlextLdifUtilitiesDN": ["flext_ldif._utilities.dn", "FlextLdifUtilitiesDN"],
    "FlextLdifUtilitiesDetection": [
        "flext_ldif._utilities.detection",
        "FlextLdifUtilitiesDetection",
    ],
    "FlextLdifUtilitiesDispatch": [
        "flext_ldif._utilities.dispatch",
        "FlextLdifUtilitiesDispatch",
    ],
    "FlextLdifUtilitiesEntry": [
        "flext_ldif._utilities.entry",
        "FlextLdifUtilitiesEntry",
    ],
    "FlextLdifUtilitiesEvents": [
        "flext_ldif._utilities.events",
        "FlextLdifUtilitiesEvents",
    ],
    "FlextLdifUtilitiesMetadata": [
        "flext_ldif._utilities.metadata",
        "FlextLdifUtilitiesMetadata",
    ],
    "FlextLdifUtilitiesOID": ["flext_ldif._utilities.oid", "FlextLdifUtilitiesOID"],
    "FlextLdifUtilitiesObjectClass": [
        "flext_ldif._utilities.object_class",
        "FlextLdifUtilitiesObjectClass",
    ],
    "FlextLdifUtilitiesParser": [
        "flext_ldif._utilities.parser",
        "FlextLdifUtilitiesParser",
    ],
    "FlextLdifUtilitiesParsers": [
        "flext_ldif._utilities.parsers",
        "FlextLdifUtilitiesParsers",
    ],
    "FlextLdifUtilitiesPipeline": [
        "flext_ldif._utilities.pipeline",
        "FlextLdifUtilitiesPipeline",
    ],
    "FlextLdifUtilitiesResult": [
        "flext_ldif._utilities.result",
        "FlextLdifUtilitiesResult",
    ],
    "FlextLdifUtilitiesSchema": [
        "flext_ldif._utilities.schema",
        "FlextLdifUtilitiesSchema",
    ],
    "FlextLdifUtilitiesServer": [
        "flext_ldif._utilities.server",
        "FlextLdifUtilitiesServer",
    ],
    "FlextLdifUtilitiesTransformer": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformer",
    ],
    "FlextLdifUtilitiesTransformers": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformers",
    ],
    "FlextLdifUtilitiesValidation": [
        "flext_ldif._utilities.validation",
        "FlextLdifUtilitiesValidation",
    ],
    "FlextLdifUtilitiesWriter": [
        "flext_ldif._utilities.writer",
        "FlextLdifUtilitiesWriter",
    ],
    "FlextLdifUtilitiesWriters": [
        "flext_ldif._utilities.writers",
        "FlextLdifUtilitiesWriters",
    ],
    "FlextLdifValidation": [
        "flext_ldif.services.rfc_validation",
        "FlextLdifValidation",
    ],
    "FlextLdifWriter": ["flext_ldif.services.writer", "FlextLdifWriter"],
    "FlextLdifWriterMixin": ["flext_ldif.services.writer", "FlextLdifWriterMixin"],
    "_models": ["flext_ldif._models", ""],
    "_utilities": ["flext_ldif._utilities", ""],
    "acl": ["flext_ldif._utilities.acl", ""],
    "ad": ["flext_ldif.servers.ad", ""],
    "analysis": ["flext_ldif.services.analysis", ""],
    "apache": ["flext_ldif.servers.apache", ""],
    "api": ["flext_ldif.api", ""],
    "attribute": ["flext_ldif._utilities.attribute", ""],
    "base": ["flext_ldif.base", ""],
    "c": ["flext_ldif.constants", "FlextLdifConstants"],
    "categorization": ["flext_ldif.services.categorization", ""],
    "collection_ldif": ["flext_ldif._utilities.collection_ldif", ""],
    "collections": ["flext_ldif._models.collections", ""],
    "constants": ["flext_ldif.constants", ""],
    "conversion": ["flext_ldif.services.conversion", ""],
    "d": ["flext_core", "d"],
    "detection": ["flext_ldif._utilities.detection", ""],
    "detector": ["flext_ldif.services.detector", ""],
    "dispatch": ["flext_ldif._utilities.dispatch", ""],
    "dn": ["flext_ldif._utilities.dn", ""],
    "domain": ["flext_ldif._models.domain", ""],
    "domain_entries": ["flext_ldif._models.domain_entries", ""],
    "ds389": ["flext_ldif.servers.ds389", ""],
    "e": ["flext_core", "e"],
    "entries": ["flext_ldif.services.entries", ""],
    "entry": ["flext_ldif._utilities.entry", ""],
    "events": ["flext_ldif._models.events", ""],
    "filters": ["flext_ldif.services.filters", ""],
    "h": ["flext_core", "h"],
    "ldif": ["flext_ldif.api", "ldif"],
    "logger": ["flext_ldif.servers.oid", "logger"],
    "m": ["flext_ldif.models", "FlextLdifModels"],
    "metadata": ["flext_ldif._models.metadata", ""],
    "migration": ["flext_ldif.services.migration", ""],
    "models": ["flext_ldif.models", ""],
    "novell": ["flext_ldif.servers.novell", ""],
    "object_class": ["flext_ldif._utilities.object_class", ""],
    "oid": ["flext_ldif._utilities.oid", ""],
    "openldap": ["flext_ldif.servers.openldap", ""],
    "openldap1": ["flext_ldif.servers.openldap1", ""],
    "oud": ["flext_ldif.servers.oud", ""],
    "p": ["flext_ldif.protocols", "FlextLdifProtocols"],
    "parser": ["flext_ldif._utilities.parser", ""],
    "parsers": ["flext_ldif._utilities.parsers", ""],
    "pipeline": ["flext_ldif._utilities.pipeline", ""],
    "processing": ["flext_ldif._models.processing", ""],
    "processing_pipeline_service": [
        "flext_ldif.services._services.processing_pipeline_service",
        "",
    ],
    "protocols": ["flext_ldif.protocols", ""],
    "r": ["flext_core", "r"],
    "relaxed": ["flext_ldif.servers.relaxed", ""],
    "result": ["flext_ldif._utilities.result", ""],
    "results": ["flext_ldif._models.results", ""],
    "rfc": ["flext_ldif.servers.rfc", ""],
    "rfc_validation": ["flext_ldif.services.rfc_validation", ""],
    "s": ["flext_ldif.base", "s"],
    "schema": ["flext_ldif._utilities.schema", ""],
    "server": ["flext_ldif._utilities.server", ""],
    "servers": ["flext_ldif.servers", ""],
    "services": ["flext_ldif.services", ""],
    "settings": ["flext_ldif.settings", ""],
    "shared": ["flext_ldif.shared", ""],
    "statistics": ["flext_ldif.services.statistics", ""],
    "t": ["flext_ldif.typings", "FlextLdifTypes"],
    "tivoli": ["flext_ldif.servers.tivoli", ""],
    "transformers": ["flext_ldif._utilities.transformers", ""],
    "typings": ["flext_ldif.typings", ""],
    "u": ["flext_ldif.utilities", "FlextLdifUtilities"],
    "utilities": ["flext_ldif.utilities", ""],
    "validation": ["flext_ldif._utilities.validation", ""],
    "writer": ["flext_ldif._utilities.writer", ""],
    "writers": ["flext_ldif._utilities.writers", ""],
    "x": ["flext_core", "x"],
}

_EXPORTS: Sequence[str] = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
