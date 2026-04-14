# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)
from flext_ldif.__version__ import *

if _t.TYPE_CHECKING:
    from flext_cli import d, e, h, r, x
    from flext_ldif._constants.base import FlextLdifConstantsBase
    from flext_ldif._constants.enums import FlextLdifConstantsEnums
    from flext_ldif._models.base import FlextLdifModelsBases
    from flext_ldif._models.collections import FlextLdifModelsCollections
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl
    from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes
    from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
    from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry
    from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata
    from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema
    from flext_ldif._models.events import FlextLdifModelsEvents
    from flext_ldif._models.metadata import FlextLdifModelsMetadata
    from flext_ldif._models.processing import FlextLdifModelsProcessing
    from flext_ldif._models.results import FlextLdifModelsResults
    from flext_ldif._models.settings import FlextLdifModelsSettings
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
    from flext_ldif._typings.base import FlextLdifTypesBase
    from flext_ldif._typings.domain import FlextLdifTypesDomain
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
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
    from flext_ldif.api import FlextLdif, ldif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.constants import FlextLdifConstants, c
    from flext_ldif.models import FlextLdifModels, m
    from flext_ldif.protocols import FlextLdifProtocols, p
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.mixins import FlextLdifQuirkMethodsMixin
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
    from flext_ldif.servers.oid import FlextLdifServersOid
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
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.rfc_validation import FlextLdifValidation
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.writer import FlextLdifWriter
    from flext_ldif.settings import FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes, t
    from flext_ldif.utilities import FlextLdifUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._constants",
        "._models",
        "._protocols",
        "._typings",
        "._utilities",
        ".servers",
        ".services",
    ),
    build_lazy_import_map(
        {
            ".__version__": (
                "__author__",
                "__author_email__",
                "__description__",
                "__license__",
                "__title__",
                "__url__",
                "__version__",
                "__version_info__",
            ),
            ".api": (
                "FlextLdif",
                "ldif",
            ),
            ".base": (
                "FlextLdifServiceBase",
                "s",
            ),
            ".constants": (
                "FlextLdifConstants",
                "c",
            ),
            ".models": (
                "FlextLdifModels",
                "m",
            ),
            ".protocols": (
                "FlextLdifProtocols",
                "p",
            ),
            ".settings": ("FlextLdifSettings",),
            ".shared": ("FlextLdifShared",),
            ".typings": (
                "FlextLdifTypes",
                "t",
            ),
            ".utilities": (
                "FlextLdifUtilities",
                "u",
            ),
            "flext_cli": (
                "d",
                "e",
                "h",
                "r",
                "x",
            ),
        },
    ),
    exclude_names=(
        "FlextDispatcher",
        "FlextLogger",
        "FlextRegistry",
        "FlextRuntime",
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifDetectorMixin",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
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
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifProcessingPipelineService",
    "FlextLdifProtocols",
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsDomain",
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
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
    "FlextLdifTypesBase",
    "FlextLdifTypesDomain",
    "FlextLdifUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesResult",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifValidation",
    "FlextLdifWriter",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "d",
    "e",
    "h",
    "ldif",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]
