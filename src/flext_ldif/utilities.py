# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from flext_cli import FlextCliUtilities

from flext_ldif import _utilities
from flext_ldif._utilities import (
    FlextLdifACLExtensionFormatting,
    FlextLdifACLExtraction,
    FlextLdifACLFormatting,
    FlextLdifACLParsing,
    FlextLdifACLPermissions,
    FlextLdifDNCharClass,
    FlextLdifDNCleaning,
    FlextLdifDNEscaping,
    FlextLdifDNNormalization,
    FlextLdifDNParsing,
    FlextLdifDNRdnParsing,
    FlextLdifDNRebasing,
    FlextLdifDNTransforming,
    FlextLdifDNValidation,
    FlextLdifEntryAccess,
    FlextLdifEntryAnalysis,
    FlextLdifEntryAttributeValidation,
    FlextLdifEntryBooleanConversion,
    FlextLdifEntryCriteria,
    FlextLdifEntryMatching,
    FlextLdifEntryOidRfcTransforming,
    FlextLdifEntryServerRules,
    FlextLdifEntryValidation,
    FlextLdifMetadataBuilders,
    FlextLdifMetadataEntryStats,
    FlextLdifMetadataJsonCore,
    FlextLdifMetadataMatchDetails,
    FlextLdifMetadataNameDescDetails,
    FlextLdifMetadataPrefixDetails,
    FlextLdifMetadataSchemaAnalysis,
    FlextLdifMetadataSyntaxOriginDetails,
    FlextLdifMetadataTracking,
    FlextLdifParserMetadataBuilders,
    FlextLdifParserRecord,
    FlextLdifParserRecordSplitter,
    FlextLdifParserSchemaFields,
    FlextLdifParserValues,
    FlextLdifServerConfig,
    FlextLdifServerDetection,
    FlextLdifServersOudUtilities,
    FlextLdifServerTypeResolution,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEntryAttrsNormalization,
    FlextLdifUtilitiesEntryDnNormalization,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaParse,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifWriterLineFolding,
    FlextLdifWriterRfcChars,
    FlextLdifWriterSchemaParts,
)
from flext_ldif._utilities._lazy_meta import FlextLdifUtilitiesLazyMeta


class FlextLdifUtilities(
    FlextLdifUtilitiesACL,
    FlextLdifACLExtraction,
    FlextLdifACLExtensionFormatting,
    FlextLdifACLPermissions,
    FlextLdifACLFormatting,
    FlextLdifACLParsing,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifDNCharClass,
    FlextLdifDNEscaping,
    FlextLdifDNParsing,
    FlextLdifDNRdnParsing,
    FlextLdifDNNormalization,
    FlextLdifDNValidation,
    FlextLdifDNCleaning,
    FlextLdifDNTransforming,
    FlextLdifDNRebasing,
    FlextLdifUtilitiesEntry,
    FlextLdifEntryAccess,
    FlextLdifEntryValidation,
    FlextLdifEntryAttributeValidation,
    FlextLdifEntryServerRules,
    FlextLdifEntryOidRfcTransforming,
    FlextLdifEntryBooleanConversion,
    FlextLdifEntryAnalysis,
    FlextLdifEntryMatching,
    FlextLdifEntryCriteria,
    FlextLdifUtilitiesEvents,
    FlextLdifServersOudUtilities,
    FlextLdifUtilitiesMetadata,
    FlextLdifMetadataJsonCore,
    FlextLdifMetadataEntryStats,
    FlextLdifMetadataBuilders,
    FlextLdifMetadataTracking,
    FlextLdifMetadataPrefixDetails,
    FlextLdifMetadataNameDescDetails,
    FlextLdifMetadataSyntaxOriginDetails,
    FlextLdifMetadataMatchDetails,
    FlextLdifMetadataSchemaAnalysis,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifParserRecord,
    FlextLdifParserRecordSplitter,
    FlextLdifParserValues,
    FlextLdifParserSchemaFields,
    FlextLdifParserMetadataBuilders,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaParse,
    FlextLdifUtilitiesServer,
    FlextLdifServerConfig,
    FlextLdifServerDetection,
    FlextLdifServerTypeResolution,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesEntryDnNormalization,
    FlextLdifUtilitiesEntryAttrsNormalization,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifWriterSchemaParts,
    FlextLdifWriterLineFolding,
    FlextLdifWriterRfcChars,
    FlextCliUtilities,
    metaclass=FlextLdifUtilitiesLazyMeta,
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """

    # NOTE (import discipline): models.py binds the ``u`` namespace while
    # flext_ldif.models is still mid-init (``u.Field`` runs at class-definition
    # time). Building the full ``Ldif`` mixin tree here would re-enter the partial
    # models module — the ``_utilities`` family evaluates ``FlextLdifModels`` at
    # class level (dispatch.py type adapters) and imports ``m`` from the package
    # root. The tree is therefore assembled lazily on first ``Ldif`` access, when
    # the package is fully initialized, making both import orders
    # (models-first and utilities-first) safe.
    _LAZY_UTILITIES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("acl", "FlextLdifUtilitiesACL"),
        ("attribute", "FlextLdifUtilitiesAttribute"),
        ("dispatch", "FlextLdifUtilitiesDispatch"),
        ("dn", "FlextLdifUtilitiesDN"),
        ("entry", "FlextLdifUtilitiesEntry"),
        ("events", "FlextLdifUtilitiesEvents"),
        ("metadata", "FlextLdifUtilitiesMetadata"),
        ("object_class", "FlextLdifUtilitiesObjectClass"),
        ("oid", "FlextLdifUtilitiesOID"),
        ("parser", "FlextLdifUtilitiesParser"),
        ("pipeline", "FlextLdifUtilitiesPipeline"),
        ("schema", "FlextLdifUtilitiesSchema"),
        ("server", "FlextLdifUtilitiesServer"),
        ("transformers", "FlextLdifUtilitiesTransformers"),
        ("validation", "FlextLdifUtilitiesValidation"),
        ("writer", "FlextLdifUtilitiesWriter"),
    )

    @staticmethod
    @lru_cache(maxsize=1)
    def build_ldif_tree() -> type:
        """Assemble the ``Ldif`` mixin tree on first access.

        The lazy, cached assembly keeps both import orders (models-first and
        utilities-first) safe: the ``_utilities`` family evaluates
        ``FlextLdifModels`` at class level, so the tree may only be built once
        the package is fully initialized. The assembled ``Ldif`` utility
        namespace class is cached on the builder function.

        Returns:
            The assembled ``Ldif`` utility namespace class.

        """
        bases: list[type] = [
            FlextLdifUtilitiesCollectionLdif.Search,
            FlextLdifUtilitiesCollectionLdif,
        ]
        family = _utilities
        for _, class_name in FlextLdifUtilities.lazy_utilities_table():
            bases.append(getattr(family, class_name))
        return type(
            "Ldif", tuple(bases), {"__doc__": "LDIF-specific utility namespace."}
        )

    @classmethod
    def lazy_utilities_table(cls) -> tuple[tuple[str, str], ...]:
        """Expose the lazy utilities registration table.

        Returns:
            The resulting ``tuple[tuple[str, str], ...]``.

        """
        return cls._LAZY_UTILITIES

    if TYPE_CHECKING:
        # Static view of the lazily assembled ``Ldif`` namespace: runtime
        # assembly stays inside the metaclass (import-order safety), while
        # this nested class makes ``Ldif.*`` statically resolvable for
        # consumers fleet-wide. It reuses the real ``_utilities`` mixin
        # classes, so signatures have a single owner.
        class Ldif(
            FlextLdifUtilitiesACL,
            FlextLdifUtilitiesAttribute,
            FlextLdifUtilitiesCollectionLdif.Search,
            FlextLdifUtilitiesCollectionLdif,
            FlextLdifUtilitiesDispatch,
            FlextLdifUtilitiesDN,
            FlextLdifUtilitiesEntry,
            FlextLdifUtilitiesEvents,
            FlextLdifUtilitiesMetadata,
            FlextLdifUtilitiesObjectClass,
            FlextLdifUtilitiesOID,
            FlextLdifUtilitiesParser,
            FlextLdifUtilitiesPipeline,
            FlextLdifUtilitiesSchema,
            FlextLdifUtilitiesServer,
            FlextLdifUtilitiesTransformers,
            FlextLdifUtilitiesValidation,
            FlextLdifUtilitiesWriter,
        ):
            """Static view of the LDIF-specific utility namespace."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
