# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from flext_cli import d, e, h, r, x
    from flext_ldif.api import FlextLdif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.constants import FlextLdifConstants, c
    from flext_ldif.models import FlextLdifModels, m
    from flext_ldif.protocols import FlextLdifProtocols, p
    from flext_ldif.services.acl import FlextLdifAcl
    from flext_ldif.services.analysis import FlextLdifAnalysis
    from flext_ldif.services.categorization import FlextLdifCategorization
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
    (".services",),
    build_lazy_import_map(
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


__all__: tuple[str, ...] = (
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
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
