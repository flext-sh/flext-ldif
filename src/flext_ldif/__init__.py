# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)
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
    from flext_cli import d, e, h, r, x
    from flext_ldif._constants.acl_convert import FlextLdifConstantsAclConvert
    from flext_ldif._constants.base import FlextLdifConstantsBase
    from flext_ldif._constants.enums import FlextLdifConstantsEnums
    from flext_ldif._models.acl_convert import FlextLdifModelsAclConvert
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
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
    from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin
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
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.conversion_acl import FlextLdifConversionAclMixin
    from flext_ldif.services.conversion_metadata import FlextLdifConversionMetadataMixin
    from flext_ldif.services.conversion_schema import FlextLdifConversionSchemaMixin
    from flext_ldif.services.conversion_support import FlextLdifConversionSupportMixin
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.transformers import FlextLdifTransformer
    from flext_ldif.services.validation import FlextLdifValidation
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
            "._constants.acl_convert": ("FlextLdifConstantsAclConvert",),
            "._constants.base": ("FlextLdifConstantsBase",),
            "._constants.enums": ("FlextLdifConstantsEnums",),
            "._models.acl_convert": ("FlextLdifModelsAclConvert",),
            "._models.base": ("FlextLdifModelsBases",),
            "._models.collections": ("FlextLdifModelsCollections",),
            "._models.domain_acl": ("FlextLdifModelsDomainAcl",),
            "._models.domain_attributes": ("FlextLdifModelsDomainAttributes",),
            "._models.domain_dn": ("FlextLdifModelsDomainDN",),
            "._models.domain_entries": ("FlextLdifModelsDomainsEntries",),
            "._models.domain_entry": ("FlextLdifModelsDomainEntry",),
            "._models.domain_metadata": ("FlextLdifModelsDomainMetadata",),
            "._models.domain_schema": ("FlextLdifModelsDomainSchema",),
            "._models.events": ("FlextLdifModelsEvents",),
            "._models.metadata": ("FlextLdifModelsMetadata",),
            "._models.processing": ("FlextLdifModelsProcessing",),
            "._models.results": ("FlextLdifModelsResults",),
            "._models.settings": ("FlextLdifModelsSettings",),
            "._protocols.base": ("FlextLdifProtocolsBase",),
            "._protocols.domain": ("FlextLdifProtocolsDomain",),
            "._typings.base": ("FlextLdifTypesBase",),
            "._typings.domain": ("FlextLdifTypesDomain",),
            "._utilities.acl": ("FlextLdifUtilitiesACL",),
            "._utilities.attribute": ("FlextLdifUtilitiesAttribute",),
            "._utilities.collection_ldif": ("FlextLdifUtilitiesCollectionLdif",),
            "._utilities.dispatch": ("FlextLdifUtilitiesDispatch",),
            "._utilities.dn": ("FlextLdifUtilitiesDN",),
            "._utilities.entry": ("FlextLdifUtilitiesEntry",),
            "._utilities.events": ("FlextLdifUtilitiesEvents",),
            "._utilities.metadata": ("FlextLdifUtilitiesMetadata",),
            "._utilities.object_class": ("FlextLdifUtilitiesObjectClass",),
            "._utilities.oid": ("FlextLdifUtilitiesOID",),
            "._utilities.parser": ("FlextLdifUtilitiesParser",),
            "._utilities.pipeline": ("FlextLdifUtilitiesPipeline",),
            "._utilities.schema": ("FlextLdifUtilitiesSchema",),
            "._utilities.server": ("FlextLdifUtilitiesServer",),
            "._utilities.transformers": (
                "FlextLdifUtilitiesTransformer",
                "FlextLdifUtilitiesTransformers",
            ),
            "._utilities.validation": ("FlextLdifUtilitiesValidation",),
            "._utilities.writer": ("FlextLdifUtilitiesWriter",),
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
            ".servers._base.acl": ("FlextLdifServersBaseSchemaAcl",),
            ".servers._base.constants": ("FlextLdifServersBaseConstants",),
            ".servers._base.entry": ("FlextLdifServersBaseEntry",),
            ".servers._base.mixins": ("FlextLdifServerMethodsMixin",),
            ".servers._base.schema": ("FlextLdifServersBaseSchema",),
            ".servers._oid.acl": ("FlextLdifServersOidAcl",),
            ".servers._oid.constants": ("FlextLdifServersOidConstants",),
            ".servers._oid.entry": ("FlextLdifServersOidEntry",),
            ".servers._oid.schema": ("FlextLdifServersOidSchema",),
            ".servers._oud.aci": ("FlextLdifServersOudAciMixin",),
            ".servers._oud.acl": ("FlextLdifServersOudAcl",),
            ".servers._oud.acl_extract": ("FlextLdifServersOudAclExtractMixin",),
            ".servers._oud.acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
            ".servers._oud.comments": ("FlextLdifServersOudCommentsMixin",),
            ".servers._oud.constants": ("FlextLdifServersOudConstants",),
            ".servers._oud.entry": ("FlextLdifServersOudEntry",),
            ".servers._oud.helpers": ("FlextLdifServersOudHelpersMixin",),
            ".servers._oud.schema": ("FlextLdifServersOudSchema",),
            ".servers._oud.transform": ("FlextLdifServersOudTransformMixin",),
            ".servers._oud.utilities": ("FlextLdifServersOudUtilities",),
            ".servers._rfc.acl": ("FlextLdifServersRfcAcl",),
            ".servers._rfc.constants": ("FlextLdifServersRfcConstants",),
            ".servers._rfc.entry": ("FlextLdifServersRfcEntry",),
            ".servers._rfc.schema": ("FlextLdifServersRfcSchema",),
            ".servers.ad": ("FlextLdifServersAd",),
            ".servers.apache": ("FlextLdifServersApache",),
            ".servers.base": ("FlextLdifServersBase",),
            ".servers.ds389": ("FlextLdifServersDs389",),
            ".servers.novell": ("FlextLdifServersNovell",),
            ".servers.oid": ("FlextLdifServersOid",),
            ".servers.openldap": ("FlextLdifServersOpenldap",),
            ".servers.openldap1": ("FlextLdifServersOpenldap1",),
            ".servers.oud": ("FlextLdifServersOud",),
            ".servers.relaxed": ("FlextLdifServersRelaxed",),
            ".servers.rfc": ("FlextLdifServersRfc",),
            ".servers.tivoli": ("FlextLdifServersTivoli",),
            ".services.acl": ("FlextLdifAcl",),
            ".services.analysis": ("FlextLdifAnalysis",),
            ".services.categorization": ("FlextLdifCategorization",),
            ".services.conversion": ("FlextLdifConversion",),
            ".services.conversion_acl": ("FlextLdifConversionAclMixin",),
            ".services.conversion_metadata": ("FlextLdifConversionMetadataMixin",),
            ".services.conversion_schema": ("FlextLdifConversionSchemaMixin",),
            ".services.conversion_support": ("FlextLdifConversionSupportMixin",),
            ".services.detector": ("FlextLdifDetector",),
            ".services.entries": ("FlextLdifEntries",),
            ".services.filters": ("FlextLdifFilters",),
            ".services.migration": ("FlextLdifMigrationPipeline",),
            ".services.parser": ("FlextLdifParser",),
            ".services.pipeline": ("FlextLdifProcessingPipeline",),
            ".services.processing": ("FlextLdifProcessing",),
            ".services.server": ("FlextLdifServer",),
            ".services.statistics": ("FlextLdifStatistics",),
            ".services.transformers": ("FlextLdifTransformer",),
            ".services.validation": ("FlextLdifValidation",),
            ".services.writer": ("FlextLdifWriter",),
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
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    [
        "__author__",
        "__author_email__",
        "__description__",
        "__license__",
        "__title__",
        "__url__",
        "__version__",
        "__version_info__",
    ],
)

__all__: list[str] = [
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifConversion",
    "FlextLdifConversionAclMixin",
    "FlextLdifConversionMetadataMixin",
    "FlextLdifConversionSchemaMixin",
    "FlextLdifConversionSupportMixin",
    "FlextLdifDetector",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifModelsAclConvert",
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
    "FlextLdifProtocols",
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsDomain",
    "FlextLdifServer",
    "FlextLdifServerMethodsMixin",
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
    "FlextLdifServersOudAciMixin",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudAclExtractMixin",
    "FlextLdifServersOudAclMetadataMixin",
    "FlextLdifServersOudCommentsMixin",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudHelpersMixin",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudTransformMixin",
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
