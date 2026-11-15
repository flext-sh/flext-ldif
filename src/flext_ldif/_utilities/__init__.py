# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.flext_ldif_servers_oud_utilities import (
        FlextLdifUtilitiesServersOud,
    )
    from flext_ldif._utilities.lazy import FlextLdifUtilitiesLazy
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesLazy",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesServersOud",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesACL": ".acl",
        "FlextLdifUtilitiesAttribute": ".attribute",
        "FlextLdifUtilitiesCollectionLdif": ".collection_ldif",
        "FlextLdifUtilitiesDN": ".dn",
        "FlextLdifUtilitiesDispatch": ".dispatch",
        "FlextLdifUtilitiesEntry": ".entry",
        "FlextLdifUtilitiesEvents": ".events",
        "FlextLdifUtilitiesLazy": ".lazy",
        "FlextLdifUtilitiesMetadata": ".metadata",
        "FlextLdifUtilitiesOID": ".oid",
        "FlextLdifUtilitiesObjectClass": ".object_class",
        "FlextLdifUtilitiesParser": ".parser",
        "FlextLdifUtilitiesPipeline": ".pipeline",
        "FlextLdifUtilitiesSchema": ".schema",
        "FlextLdifUtilitiesServer": ".server",
        "FlextLdifUtilitiesServersOud": ".flext_ldif_servers_oud_utilities",
        "FlextLdifUtilitiesTransformers": ".transformers",
        "FlextLdifUtilitiesValidation": ".validation",
        "FlextLdifUtilitiesWriter": ".writer",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesACL": (),
        "FlextLdifUtilitiesAttribute": (),
        "FlextLdifUtilitiesCollectionLdif": (
            "Search",
            "deduplicate_preserve_order",
            "normalize_ldif",
            "nz",
        ),
        "FlextLdifUtilitiesDN": (),
        "FlextLdifUtilitiesDispatch": (
            "_ENTRY_LIST_ADAPTER",
            "_ACL_LIST_ADAPTER",
            "as_entry",
            "as_entries",
            "as_acl",
            "as_acls",
            "parse_definition",
            "validate",
            "_validate_entries",
            "_is_entry_sequence",
        ),
        "FlextLdifUtilitiesEntry": (),
        "FlextLdifUtilitiesEvents": (
            "_build_conversion_event_logging",
            "_log_and_emit_generic_event",
            "_process_extras",
            "_to_error_details_list",
            "create_conversion_event",
            "create_dn_event",
            "log_and_emit_conversion_event",
            "log_and_emit_dn_event",
        ),
        "FlextLdifUtilitiesLazy": (),
        "FlextLdifUtilitiesMetadata": (),
        "FlextLdifUtilitiesOID": (),
        "FlextLdifUtilitiesObjectClass": (),
        "FlextLdifUtilitiesParser": (),
        "FlextLdifUtilitiesPipeline": (
            "ValidationResult",
            "ValidationPipeline",
        ),
        "FlextLdifUtilitiesSchema": (),
        "FlextLdifUtilitiesServer": (),
        "FlextLdifUtilitiesServersOud": ("resolve_parser_config",),
        "FlextLdifUtilitiesTransformers": (),
        "FlextLdifUtilitiesValidation": (),
        "FlextLdifUtilitiesWriter": (),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextLdifUtilitiesACL": (
            ("flext_ldif._utilities._acl", "FlextLdifUtilitiesACLExtensions"),
            ("flext_ldif._utilities._acl", "FlextLdifUtilitiesACLExtract"),
            ("flext_ldif._utilities._acl", "FlextLdifUtilitiesACLFormat"),
            ("flext_ldif._utilities._acl", "FlextLdifUtilitiesACLParse"),
            ("flext_ldif._utilities._acl", "FlextLdifUtilitiesACLPermissions"),
        ),
        "FlextLdifUtilitiesAttribute": (
            (
                "flext_ldif._utilities._attribute",
                "FlextLdifUtilitiesAttributeValidation",
            ),
        ),
        "FlextLdifUtilitiesDN": (
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNChars"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNClean"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNEscape"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNHierarchy"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNNormalize"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNParse"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNRdn"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNRebase"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNTransform"),
            ("flext_ldif._utilities._dn", "FlextLdifUtilitiesDNValidate"),
        ),
        "FlextLdifUtilitiesEntry": (
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryAccess"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryAnalysis"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryAttrValidation"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryBoolean"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryCriteria"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryMatching"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryOidRfc"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryRfcViolations"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryServerRules"),
            ("flext_ldif._utilities._entry", "FlextLdifUtilitiesEntryValidation"),
        ),
        "FlextLdifUtilitiesLazy": (
            ("flext_ldif._utilities._lazy", "FlextLdifUtilitiesLazyTree"),
        ),
        "FlextLdifUtilitiesMetadata": (
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataBuilders"),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataEntryStats"),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataJsonCore"),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataMatch"),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataNameDesc"),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataPrefix"),
            (
                "flext_ldif._utilities._metadata",
                "FlextLdifUtilitiesMetadataSchemaAnalysis",
            ),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataSpacing"),
            (
                "flext_ldif._utilities._metadata",
                "FlextLdifUtilitiesMetadataSyntaxOrigin",
            ),
            ("flext_ldif._utilities._metadata", "FlextLdifUtilitiesMetadataTracking"),
        ),
        "FlextLdifUtilitiesOID": (
            ("flext_ldif._utilities._oid", "FlextLdifUtilitiesOIDOperations"),
        ),
        "FlextLdifUtilitiesObjectClass": (
            ("flext_ldif._utilities._object_class", "FlextLdifUtilitiesObjectClassFix"),
        ),
        "FlextLdifUtilitiesParser": (
            ("flext_ldif._utilities._parser", "FlextLdifUtilitiesParserMetadata"),
            ("flext_ldif._utilities._parser", "FlextLdifUtilitiesParserRecord"),
            ("flext_ldif._utilities._parser", "FlextLdifUtilitiesParserRecords"),
            ("flext_ldif._utilities._parser", "FlextLdifUtilitiesParserSchemaFields"),
            ("flext_ldif._utilities._parser", "FlextLdifUtilitiesParserValues"),
        ),
        "FlextLdifUtilitiesSchema": (
            ("flext_ldif._utilities._schema", "FlextLdifUtilitiesSchemaBuild"),
            ("flext_ldif._utilities._schema", "FlextLdifUtilitiesSchemaExtract"),
            ("flext_ldif._utilities._schema", "FlextLdifUtilitiesSchemaFormat"),
            ("flext_ldif._utilities._schema", "FlextLdifUtilitiesSchemaNormalize"),
            ("flext_ldif._utilities._schema", "FlextLdifUtilitiesSchemaParse"),
        ),
        "FlextLdifUtilitiesServer": (
            ("flext_ldif._utilities._server", "FlextLdifUtilitiesServerConfig"),
            ("flext_ldif._utilities._server", "FlextLdifUtilitiesServerDetect"),
            ("flext_ldif._utilities._server", "FlextLdifUtilitiesServerServerType"),
        ),
        "FlextLdifUtilitiesTransformers": (
            (
                "flext_ldif._utilities._transformers",
                "FlextLdifUtilitiesTransformersAttrs",
            ),
            ("flext_ldif._utilities._transformers", "FlextLdifUtilitiesTransformersDn"),
        ),
        "FlextLdifUtilitiesValidation": (
            (
                "flext_ldif._utilities._validation",
                "FlextLdifUtilitiesValidationLdifValue",
            ),
            ("flext_ldif._utilities._validation", "FlextLdifUtilitiesValidationRfc"),
        ),
        "FlextLdifUtilitiesWriter": (
            ("flext_ldif._utilities._writer", "FlextLdifUtilitiesWriterChars"),
            ("flext_ldif._utilities._writer", "FlextLdifUtilitiesWriterFold"),
            ("flext_ldif._utilities._writer", "FlextLdifUtilitiesWriterSchema"),
        ),
    },
)
