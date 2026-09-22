# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

from .__version__ import (
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
    from flext_cli import (
        cli,
        core,
        d,
        e,
        from_json,
        h,
        lazy_attribute,
        r,
        to_json,
        to_jsonable_python,
        x,
    )

    from . import servers, services
    from ._config import FlextLdifConfig, config
    from ._settings import FlextLdifSettings, settings
    from .api import FlextLdif, ldif
    from .base import FlextLdifServiceBase, s
    from .cli import main
    from .constants import FlextLdifConstants, c
    from .models import FlextLdifModels, m
    from .protocols import FlextLdifProtocols, p
    from .servers.ad import FlextLdifServersAd
    from .servers.apache import FlextLdifServersApache
    from .servers.base import FlextLdifServersBase
    from .servers.ds389 import FlextLdifServersDs389
    from .servers.oid import (
        FlextLdifServersOid,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from .servers.openldap import FlextLdifServersOpenldap
    from .servers.oud import FlextLdifServersOud
    from .servers.relaxed import FlextLdifServersRelaxed
    from .servers.rfc import FlextLdifServersRfc
    from .servers.tivoli import FlextLdifServersTivoli
    from .services.acl import FlextLdifAcl
    from .services.analysis import FlextLdifAnalysis
    from .services.categorization import FlextLdifCategorization
    from .services.conversion import FlextLdifConversion
    from .services.conversion_acl import FlextLdifConversionAclMixin
    from .services.conversion_acl_preserve import FlextLdifConversionAclPreserveMixin
    from .services.conversion_entry import FlextLdifConversionEntryMixin
    from .services.conversion_metadata import FlextLdifConversionMetadataMixin
    from .services.conversion_schema import FlextLdifConversionSchemaMixin
    from .services.conversion_schema_entry import FlextLdifConversionSchemaEntryMixin
    from .services.conversion_support import FlextLdifConversionSupportMixin
    from .services.detector import FlextLdifDetector
    from .services.entries import FlextLdifEntries
    from .services.filters import FlextLdifFilters
    from .services.migration import FlextLdifMigrationPipeline
    from .services.parser import FlextLdifParser
    from .services.processing import FlextLdifProcessing
    from .services.server import FlextLdifServer
    from .services.statistics import FlextLdifStatistics
    from .services.validation import FlextLdifValidation
    from .services.writer import FlextLdifWriter
    from .shared import FlextLdifShared
    from .typings import FlextLdifTypes, t
    from .utilities import FlextLdifUtilities, u
__all__: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConfig",
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
    "FlextLdifProtocols",
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersOid",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifStatistics",
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
    "cli",
    "config",
    "core",
    "d",
    "e",
    "from_json",
    "h",
    "lazy_attribute",
    "ldif",
    "m",
    "main",
    "p",
    "r",
    "s",
    "servers",
    "services",
    "settings",
    "t",
    "to_json",
    "to_jsonable_python",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._config": ("FlextLdifConfig", "config"),
            "._settings": ("FlextLdifSettings", "settings"),
            ".api": ("FlextLdif", "ldif"),
            ".base": ("FlextLdifServiceBase", "s"),
            ".cli": ("main",),
            ".constants": ("FlextLdifConstants", "c"),
            ".models": ("FlextLdifModels", "m"),
            ".protocols": ("FlextLdifProtocols", "p"),
            ".servers": ("servers",),
            ".servers.ad": ("FlextLdifServersAd",),
            ".servers.apache": ("FlextLdifServersApache",),
            ".servers.base": ("FlextLdifServersBase",),
            ".servers.ds389": ("FlextLdifServersDs389",),
            ".servers.oid": (
                "FlextLdifServersOid",
                "FlextLdifServersOidConstants",
                "FlextLdifServersOidEntry",
                "FlextLdifServersOidSchema",
            ),
            ".servers.openldap": ("FlextLdifServersOpenldap",),
            ".servers.oud": ("FlextLdifServersOud",),
            ".servers.relaxed": ("FlextLdifServersRelaxed",),
            ".servers.rfc": ("FlextLdifServersRfc",),
            ".servers.tivoli": ("FlextLdifServersTivoli",),
            ".services": ("services",),
            ".services.acl": ("FlextLdifAcl",),
            ".services.analysis": ("FlextLdifAnalysis",),
            ".services.categorization": ("FlextLdifCategorization",),
            ".services.conversion": ("FlextLdifConversion",),
            ".services.conversion_acl": ("FlextLdifConversionAclMixin",),
            ".services.conversion_acl_preserve": (
                "FlextLdifConversionAclPreserveMixin",
            ),
            ".services.conversion_entry": ("FlextLdifConversionEntryMixin",),
            ".services.conversion_metadata": ("FlextLdifConversionMetadataMixin",),
            ".services.conversion_schema": ("FlextLdifConversionSchemaMixin",),
            ".services.conversion_schema_entry": (
                "FlextLdifConversionSchemaEntryMixin",
            ),
            ".services.conversion_support": ("FlextLdifConversionSupportMixin",),
            ".services.detector": ("FlextLdifDetector",),
            ".services.entries": ("FlextLdifEntries",),
            ".services.filters": ("FlextLdifFilters",),
            ".services.migration": ("FlextLdifMigrationPipeline",),
            ".services.parser": ("FlextLdifParser",),
            ".services.processing": ("FlextLdifProcessing",),
            ".services.server": ("FlextLdifServer",),
            ".services.statistics": ("FlextLdifStatistics",),
            ".services.validation": ("FlextLdifValidation",),
            ".services.writer": ("FlextLdifWriter",),
            ".shared": ("FlextLdifShared",),
            ".typings": ("FlextLdifTypes", "t"),
            ".utilities": ("FlextLdifUtilities", "u"),
            "flext_cli": (
                "cli",
                "core",
                "d",
                "e",
                "from_json",
                "h",
                "lazy_attribute",
                "r",
                "to_json",
                "to_jsonable_python",
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
