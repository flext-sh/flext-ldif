# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes, d, e, h, r, x

    from flext_ldif import _models, _utilities, servers, services
    from flext_ldif.__version__ import (
        __all__,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
    )
    from flext_ldif._models.base import FlextLdifModelsBases
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.domain import FlextLdifModelsDomains
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.metadata import FlextLdifModelsMetadata
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters
    from flext_ldif.api import FlextLdif, ldif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.constants import FlextLdifConstants, FlextLdifConstants as c
    from flext_ldif.models import FlextLdifModels, FlextLdifModels as m
    from flext_ldif.protocols import FlextLdifProtocols, FlextLdifProtocols as p
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
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid, logger
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli
    from flext_ldif.services._services.processing_pipeline_service import (
        FlextLdifProcessingPipelineService,
    )
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.detector import FlextLdifDetector, FlextLdifDetectorMixin
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser, FlextLdifParserMixin
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.rfc_validation import FlextLdifValidation
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.writer import FlextLdifWriter, FlextLdifWriterMixin
    from flext_ldif.settings import FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes, FlextLdifTypes as t
    from flext_ldif.utilities import FlextLdifUtilities, FlextLdifUtilities as u

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
    "__all__": ["flext_ldif.__version__", "__all__"],
    "__author__": ["flext_ldif.__version__", "__author__"],
    "__author_email__": ["flext_ldif.__version__", "__author_email__"],
    "__description__": ["flext_ldif.__version__", "__description__"],
    "__license__": ["flext_ldif.__version__", "__license__"],
    "__title__": ["flext_ldif.__version__", "__title__"],
    "__url__": ["flext_ldif.__version__", "__url__"],
    "__version__": ["flext_ldif.__version__", "__version__"],
    "__version_info__": ["flext_ldif.__version__", "__version_info__"],
    "_models": ["flext_ldif._models", ""],
    "_utilities": ["flext_ldif._utilities", ""],
    "c": ["flext_ldif.constants", "FlextLdifConstants"],
    "d": ["flext_core", "d"],
    "e": ["flext_core", "e"],
    "h": ["flext_core", "h"],
    "ldif": ["flext_ldif.api", "ldif"],
    "logger": ["flext_ldif.servers.oid", "logger"],
    "m": ["flext_ldif.models", "FlextLdifModels"],
    "p": ["flext_ldif.protocols", "FlextLdifProtocols"],
    "r": ["flext_core", "r"],
    "s": ["flext_ldif.base", "s"],
    "servers": ["flext_ldif.servers", ""],
    "services": ["flext_ldif.services", ""],
    "t": ["flext_ldif.typings", "FlextLdifTypes"],
    "u": ["flext_ldif.utilities", "FlextLdifUtilities"],
    "x": ["flext_core", "x"],
}

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
    "__all__",
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
    "c",
    "d",
    "e",
    "h",
    "ldif",
    "logger",
    "m",
    "p",
    "r",
    "s",
    "servers",
    "services",
    "t",
    "u",
    "x",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
