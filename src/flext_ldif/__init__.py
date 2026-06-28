# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
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
    from flext_cli import d as d, e as e, h as h, r as r, x as x
    from flext_ldif.api import FlextLdif as FlextLdif, ldif as ldif
    from flext_ldif.base import FlextLdifServiceBase as FlextLdifServiceBase, s as s
    from flext_ldif.constants import FlextLdifConstants as FlextLdifConstants, c as c
    from flext_ldif.models import FlextLdifModels as FlextLdifModels, m as m
    from flext_ldif.protocols import FlextLdifProtocols as FlextLdifProtocols, p as p
    from flext_ldif.servers.ad import FlextLdifServersAd as FlextLdifServersAd
    from flext_ldif.servers.apache import (
        FlextLdifServersApache as FlextLdifServersApache,
    )
    from flext_ldif.servers.base import FlextLdifServersBase as FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389 as FlextLdifServersDs389
    from flext_ldif.servers.novell import (
        FlextLdifServersNovell as FlextLdifServersNovell,
    )
    from flext_ldif.servers.oid import FlextLdifServersOid as FlextLdifServersOid
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
    from flext_ldif.services.acl import FlextLdifAcl as FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis as FlextLdifAnalysis
    from flext_ldif.services.categorization import (
        FlextLdifCategorization as FlextLdifCategorization,
    )
    from flext_ldif.services.conversion import (
        FlextLdifConversion as FlextLdifConversion,
    )
    from flext_ldif.services.conversion_acl import (
        FlextLdifConversionAclMixin as FlextLdifConversionAclMixin,
    )
    from flext_ldif.services.conversion_acl_preserve import (
        FlextLdifConversionAclPreserveMixin as FlextLdifConversionAclPreserveMixin,
    )
    from flext_ldif.services.conversion_entry import (
        FlextLdifConversionEntryMixin as FlextLdifConversionEntryMixin,
    )
    from flext_ldif.services.conversion_metadata import (
        FlextLdifConversionMetadataMixin as FlextLdifConversionMetadataMixin,
    )
    from flext_ldif.services.conversion_schema import (
        FlextLdifConversionSchemaMixin as FlextLdifConversionSchemaMixin,
    )
    from flext_ldif.services.conversion_schema_entry import (
        FlextLdifConversionSchemaEntryMixin as FlextLdifConversionSchemaEntryMixin,
    )
    from flext_ldif.services.conversion_support import (
        FlextLdifConversionSupportMixin as FlextLdifConversionSupportMixin,
    )
    from flext_ldif.services.detector import FlextLdifDetector as FlextLdifDetector
    from flext_ldif.services.entries import FlextLdifEntries as FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters as FlextLdifFilters
    from flext_ldif.services.migration import (
        FlextLdifMigrationPipeline as FlextLdifMigrationPipeline,
    )
    from flext_ldif.services.parser import FlextLdifParser as FlextLdifParser
    from flext_ldif.services.pipeline import (
        FlextLdifProcessingPipeline as FlextLdifProcessingPipeline,
    )
    from flext_ldif.services.processing import (
        FlextLdifProcessing as FlextLdifProcessing,
    )
    from flext_ldif.services.server import FlextLdifServer as FlextLdifServer
    from flext_ldif.services.statistics import (
        FlextLdifStatistics as FlextLdifStatistics,
    )
    from flext_ldif.services.transformers import (
        FlextLdifTransformer as FlextLdifTransformer,
    )
    from flext_ldif.services.validation import (
        FlextLdifValidation as FlextLdifValidation,
    )
    from flext_ldif.services.writer import FlextLdifWriter as FlextLdifWriter
    from flext_ldif.settings import FlextLdifSettings as FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared as FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes as FlextLdifTypes, t as t
    from flext_ldif.utilities import FlextLdifUtilities as FlextLdifUtilities, u as u
_LAZY_IMPORTS = build_lazy_import_map(
    {
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
        ".services.conversion_acl_preserve": ("FlextLdifConversionAclPreserveMixin",),
        ".services.conversion_entry": ("FlextLdifConversionEntryMixin",),
        ".services.conversion_metadata": ("FlextLdifConversionMetadataMixin",),
        ".services.conversion_schema": ("FlextLdifConversionSchemaMixin",),
        ".services.conversion_schema_entry": ("FlextLdifConversionSchemaEntryMixin",),
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
    "FlextLdifConversion",
    "FlextLdifConversionAclMixin",
    "FlextLdifConversionAclPreserveMixin",
    "FlextLdifConversionEntryMixin",
    "FlextLdifConversionMetadataMixin",
    "FlextLdifConversionSchemaEntryMixin",
    "FlextLdifConversionSchemaMixin",
    "FlextLdifConversionSupportMixin",
    "FlextLdifDetector",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifProtocols",
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifStatistics",
    "FlextLdifTransformer",
    "FlextLdifTypes",
    "FlextLdifUtilities",
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
