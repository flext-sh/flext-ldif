# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports
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

if TYPE_CHECKING:
    from flext_cli import d, e, h, r, x

    from flext_ldif import servers, services
    from flext_ldif._config import FlextLdifConfig, config
    from flext_ldif._settings import FlextLdifSettings, settings
    from flext_ldif.api import FlextLdif, ldif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.cli import main
    from flext_ldif.constants import FlextLdifConstants, c
    from flext_ldif.models import FlextLdifModels, m
    from flext_ldif.protocols import FlextLdifProtocols, p
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.oid import (
        FlextLdifServersOid,
        FlextLdifServersOidAclAssemble,
        FlextLdifServersOidAclConvert,
        FlextLdifServersOidAclPipeline,
        FlextLdifServersOidAclRender,
        FlextLdifServersOidAclToOud,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1_entry import FlextLdifServersOpenldap1Entry
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.relaxed_entry import FlextLdifServersRelaxedEntry
    from flext_ldif.servers.relaxed_entry_parse import (
        FlextLdifServersRelaxedEntryParseMixin,
    )
    from flext_ldif.servers.relaxed_entry_write import (
        FlextLdifServersRelaxedEntryWriteMixin,
    )
    from flext_ldif.servers.relaxed_schema import FlextLdifServersRelaxedSchema
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
    from flext_ldif.services.categorization_filtering import (
        FlextLdifCategorizationFiltering,
    )
    from flext_ldif.services.categorization_rules import FlextLdifCategorizationRules
    from flext_ldif.services.conversion import FlextLdifConversion
    from flext_ldif.services.conversion_acl import FlextLdifConversionAclMixin
    from flext_ldif.services.conversion_acl_preserve import (
        FlextLdifConversionAclPreserveMixin,
    )
    from flext_ldif.services.conversion_entry import FlextLdifConversionEntryMixin
    from flext_ldif.services.conversion_metadata import FlextLdifConversionMetadataMixin
    from flext_ldif.services.conversion_schema import FlextLdifConversionSchemaMixin
    from flext_ldif.services.conversion_schema_entry import (
        FlextLdifConversionSchemaEntryMixin,
    )
    from flext_ldif.services.conversion_support import FlextLdifConversionSupportMixin
    from flext_ldif.services.detector import FlextLdifDetector
    from flext_ldif.services.detector_scoring import FlextLdifDetectorScoring
    from flext_ldif.services.entries import FlextLdifEntries
    from flext_ldif.services.filters import FlextLdifFilters
    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from flext_ldif.services.parser import FlextLdifParser
    from flext_ldif.services.processing import FlextLdifProcessing
    from flext_ldif.services.server import FlextLdifServer
    from flext_ldif.services.statistics import FlextLdifStatistics
    from flext_ldif.services.validation import FlextLdifValidation
    from flext_ldif.services.writer import FlextLdifWriter
    from flext_ldif.shared import FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes, t
    from flext_ldif.utilities import FlextLdifUtilities, u


__all__: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifCategorizationFiltering",
    "FlextLdifCategorizationRules",
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
    "FlextLdifDetectorScoring",
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
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1Entry",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRelaxedEntry",
    "FlextLdifServersRelaxedEntryParseMixin",
    "FlextLdifServersRelaxedEntryWriteMixin",
    "FlextLdifServersRelaxedSchema",
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
    "config",
    "d",
    "e",
    "h",
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
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdif": ".api",
        "FlextLdifAcl": ".services.acl",
        "FlextLdifAnalysis": ".services.analysis",
        "FlextLdifCategorization": ".services.categorization",
        "FlextLdifCategorizationFiltering": ".services.categorization_filtering",
        "FlextLdifCategorizationRules": ".services.categorization_rules",
        "FlextLdifConfig": "._config",
        "FlextLdifConstants": ".constants",
        "FlextLdifConversion": ".services.conversion",
        "FlextLdifConversionAclMixin": ".services.conversion_acl",
        "FlextLdifConversionAclPreserveMixin": ".services.conversion_acl_preserve",
        "FlextLdifConversionEntryMixin": ".services.conversion_entry",
        "FlextLdifConversionMetadataMixin": ".services.conversion_metadata",
        "FlextLdifConversionSchemaEntryMixin": ".services.conversion_schema_entry",
        "FlextLdifConversionSchemaMixin": ".services.conversion_schema",
        "FlextLdifConversionSupportMixin": ".services.conversion_support",
        "FlextLdifDetector": ".services.detector",
        "FlextLdifDetectorScoring": ".services.detector_scoring",
        "FlextLdifEntries": ".services.entries",
        "FlextLdifFilters": ".services.filters",
        "FlextLdifMigrationPipeline": ".services.migration",
        "FlextLdifModels": ".models",
        "FlextLdifParser": ".services.parser",
        "FlextLdifProcessing": ".services.processing",
        "FlextLdifProtocols": ".protocols",
        "FlextLdifServer": ".services.server",
        "FlextLdifServersAd": ".servers.ad",
        "FlextLdifServersApache": ".servers.apache",
        "FlextLdifServersBase": ".servers.base",
        "FlextLdifServersDs389": ".servers.ds389",
        "FlextLdifServersOid": ".servers.oid",
        "FlextLdifServersOidAclAssemble": ".servers.oid",
        "FlextLdifServersOidAclConvert": ".servers.oid",
        "FlextLdifServersOidAclPipeline": ".servers.oid",
        "FlextLdifServersOidAclRender": ".servers.oid",
        "FlextLdifServersOidAclToOud": ".servers.oid",
        "FlextLdifServersOidConstants": ".servers.oid",
        "FlextLdifServersOidEntry": ".servers.oid",
        "FlextLdifServersOidSchema": ".servers.oid",
        "FlextLdifServersOpenldap": ".servers.openldap",
        "FlextLdifServersOpenldap1Entry": ".servers.openldap1_entry",
        "FlextLdifServersOud": ".servers.oud",
        "FlextLdifServersRelaxed": ".servers.relaxed",
        "FlextLdifServersRelaxedEntry": ".servers.relaxed_entry",
        "FlextLdifServersRelaxedEntryParseMixin": ".servers.relaxed_entry_parse",
        "FlextLdifServersRelaxedEntryWriteMixin": ".servers.relaxed_entry_write",
        "FlextLdifServersRelaxedSchema": ".servers.relaxed_schema",
        "FlextLdifServersRfc": ".servers.rfc",
        "FlextLdifServersTivoli": ".servers.tivoli",
        "FlextLdifServiceBase": ".base",
        "FlextLdifSettings": "._settings",
        "FlextLdifShared": ".shared",
        "FlextLdifStatistics": ".services.statistics",
        "FlextLdifTypes": ".typings",
        "FlextLdifUtilities": ".utilities",
        "FlextLdifValidation": ".services.validation",
        "FlextLdifWriter": ".services.writer",
        "c": ".constants",
        "config": "._config",
        "d": "flext_cli",
        "e": "flext_cli",
        "h": "flext_cli",
        "ldif": ".api",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "r": "flext_cli",
        "s": ".base",
        "servers": ".servers",
        "services": ".services",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_cli",
    }),
    public_exports=__all__,
)
