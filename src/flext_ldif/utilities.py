"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from flext_cli import FlextCliUtilities

from flext_ldif import _utilities
from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
from flext_ldif._utilities._lazy_meta import FlextLdifUtilitiesLazyMeta
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif._utilities._acl_extensions import FlextLdifACLExtensionFormatting
from flext_ldif._utilities._acl_extract import FlextLdifACLExtraction
from flext_ldif._utilities._acl_format import FlextLdifACLFormatting
from flext_ldif._utilities._acl_parse import FlextLdifACLParsing
from flext_ldif._utilities._acl_permissions import FlextLdifACLPermissions
from flext_ldif._utilities._dn_chars import FlextLdifDNCharClass
from flext_ldif._utilities._dn_clean import FlextLdifDNCleaning
from flext_ldif._utilities._dn_escape import FlextLdifDNEscaping
from flext_ldif._utilities._dn_normalize import FlextLdifDNNormalization
from flext_ldif._utilities._dn_parse import FlextLdifDNParsing
from flext_ldif._utilities._dn_rdn import FlextLdifDNRdnParsing
from flext_ldif._utilities._dn_rebase import FlextLdifDNRebasing
from flext_ldif._utilities._dn_transform import FlextLdifDNTransforming
from flext_ldif._utilities._dn_validate import FlextLdifDNValidation
from flext_ldif._utilities._entry_access import FlextLdifEntryAccess
from flext_ldif._utilities._entry_boolean import FlextLdifEntryBooleanConversion
from flext_ldif._utilities._entry_criteria import FlextLdifEntryCriteria
from flext_ldif._utilities._entry_matching import FlextLdifEntryMatching
from flext_ldif._utilities._entry_oid_rfc import FlextLdifEntryOidRfcTransforming
from flext_ldif._utilities._metadata_builders import FlextLdifMetadataBuilders
from flext_ldif._utilities._metadata_entry_stats import FlextLdifMetadataEntryStats
from flext_ldif._utilities._metadata_json_core import FlextLdifMetadataJsonCore
from flext_ldif._utilities._metadata_match import FlextLdifMetadataMatchDetails
from flext_ldif._utilities._metadata_name_desc import FlextLdifMetadataNameDescDetails
from flext_ldif._utilities._metadata_prefix import FlextLdifMetadataPrefixDetails
from flext_ldif._utilities._metadata_schema_analysis import FlextLdifMetadataSchemaAnalysis
from flext_ldif._utilities._metadata_syntax_origin import FlextLdifMetadataSyntaxOriginDetails
from flext_ldif._utilities._metadata_tracking import FlextLdifMetadataTracking
from flext_ldif._utilities._parser_metadata import FlextLdifParserMetadataBuilders
from flext_ldif._utilities._parser_record import FlextLdifParserRecord
from flext_ldif._utilities._parser_records import FlextLdifParserRecordSplitter
from flext_ldif._utilities._parser_schema_fields import FlextLdifParserSchemaFields
from flext_ldif._utilities._parser_values import FlextLdifParserValues
from flext_ldif._utilities._server_config import FlextLdifServerConfig
from flext_ldif._utilities._server_detect import FlextLdifServerDetection
from flext_ldif._utilities._server_type import FlextLdifServerTypeResolution
from flext_ldif._utilities._transformer_attrs import FlextLdifUtilitiesEntryAttrsNormalization
from flext_ldif._utilities._transformer_dn import FlextLdifUtilitiesEntryDnNormalization
from flext_ldif._utilities._writer_chars import FlextLdifWriterRfcChars
from flext_ldif._utilities._writer_fold import FlextLdifWriterLineFolding
from flext_ldif._utilities._writer_schema import FlextLdifWriterSchemaParts
from flext_ldif._utilities.schema_build import FlextLdifUtilitiesSchemaBuild
from flext_ldif._utilities.schema_extract import FlextLdifUtilitiesSchemaExtract
from flext_ldif._utilities.schema_format import FlextLdifUtilitiesSchemaFormat
from flext_ldif._utilities.schema_normalize import FlextLdifUtilitiesSchemaNormalize
from flext_ldif._utilities.schema_parse import FlextLdifUtilitiesSchemaParse

if TYPE_CHECKING:
    from flext_ldif._utilities import (
        FlextLdifUtilitiesObjectClass,
        )


from flext_ldif._utilities._entry_analysis import FlextLdifEntryAnalysis
from flext_ldif._utilities._entry_attr_validation import (
    FlextLdifEntryAttributeValidation,
)
from flext_ldif._utilities._entry_server_rules import FlextLdifEntryServerRules
from flext_ldif._utilities._entry_validation import FlextLdifEntryValidation


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
