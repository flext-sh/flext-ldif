# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
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
    from flext_ldif._utilities._entry_analysis import FlextLdifEntryAnalysis
    from flext_ldif._utilities._entry_attr_validation import (
        FlextLdifEntryAttributeValidation,
    )
    from flext_ldif._utilities._entry_boolean import FlextLdifEntryBooleanConversion
    from flext_ldif._utilities._entry_criteria import FlextLdifEntryCriteria
    from flext_ldif._utilities._entry_matching import FlextLdifEntryMatching
    from flext_ldif._utilities._entry_oid_rfc import FlextLdifEntryOidRfcTransforming
    from flext_ldif._utilities._entry_server_rules import FlextLdifEntryServerRules
    from flext_ldif._utilities._entry_validation import FlextLdifEntryValidation
    from flext_ldif._utilities._metadata_builders import FlextLdifMetadataBuilders
    from flext_ldif._utilities._metadata_entry_stats import FlextLdifMetadataEntryStats
    from flext_ldif._utilities._metadata_json_core import FlextLdifMetadataJsonCore
    from flext_ldif._utilities._metadata_match import FlextLdifMetadataMatchDetails
    from flext_ldif._utilities._metadata_name_desc import (
        FlextLdifMetadataNameDescDetails,
    )
    from flext_ldif._utilities._metadata_prefix import FlextLdifMetadataPrefixDetails
    from flext_ldif._utilities._metadata_schema_analysis import (
        FlextLdifMetadataSchemaAnalysis,
    )
    from flext_ldif._utilities._metadata_syntax_origin import (
        FlextLdifMetadataSyntaxOriginDetails,
    )
    from flext_ldif._utilities._metadata_tracking import FlextLdifMetadataTracking
    from flext_ldif._utilities._parser_metadata import FlextLdifParserMetadataBuilders
    from flext_ldif._utilities._parser_record import FlextLdifParserRecord
    from flext_ldif._utilities._parser_records import FlextLdifParserRecordSplitter
    from flext_ldif._utilities._parser_schema_fields import FlextLdifParserSchemaFields
    from flext_ldif._utilities._parser_values import FlextLdifParserValues
    from flext_ldif._utilities._server_config import FlextLdifServerConfig
    from flext_ldif._utilities._server_detect import FlextLdifServerDetection
    from flext_ldif._utilities._server_type import FlextLdifServerTypeResolution
    from flext_ldif._utilities._transformer_attrs import (
        FlextLdifUtilitiesEntryAttrsNormalization,
    )
    from flext_ldif._utilities._transformer_dn import (
        FlextLdifUtilitiesEntryDnNormalization,
    )
    from flext_ldif._utilities._writer_chars import FlextLdifWriterRfcChars
    from flext_ldif._utilities._writer_fold import FlextLdifWriterLineFolding
    from flext_ldif._utilities._writer_schema import FlextLdifWriterSchemaParts
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.flext_ldif_servers_oud_utilities import (
        FlextLdifServersOudUtilities,
    )
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.schema_build import FlextLdifUtilitiesSchemaBuild
    from flext_ldif._utilities.schema_extract import FlextLdifUtilitiesSchemaExtract
    from flext_ldif._utilities.schema_format import FlextLdifUtilitiesSchemaFormat
    from flext_ldif._utilities.schema_normalize import FlextLdifUtilitiesSchemaNormalize
    from flext_ldif._utilities.schema_parse import FlextLdifUtilitiesSchemaParse
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter


__all__: tuple[str, ...] = (
    "FlextLdifACLExtensionFormatting",
    "FlextLdifACLExtraction",
    "FlextLdifACLFormatting",
    "FlextLdifACLParsing",
    "FlextLdifACLPermissions",
    "FlextLdifDNCharClass",
    "FlextLdifDNCleaning",
    "FlextLdifDNEscaping",
    "FlextLdifDNNormalization",
    "FlextLdifDNParsing",
    "FlextLdifDNRdnParsing",
    "FlextLdifDNRebasing",
    "FlextLdifDNTransforming",
    "FlextLdifDNValidation",
    "FlextLdifEntryAccess",
    "FlextLdifEntryAnalysis",
    "FlextLdifEntryAttributeValidation",
    "FlextLdifEntryBooleanConversion",
    "FlextLdifEntryCriteria",
    "FlextLdifEntryMatching",
    "FlextLdifEntryOidRfcTransforming",
    "FlextLdifEntryServerRules",
    "FlextLdifEntryValidation",
    "FlextLdifMetadataBuilders",
    "FlextLdifMetadataEntryStats",
    "FlextLdifMetadataJsonCore",
    "FlextLdifMetadataMatchDetails",
    "FlextLdifMetadataNameDescDetails",
    "FlextLdifMetadataPrefixDetails",
    "FlextLdifMetadataSchemaAnalysis",
    "FlextLdifMetadataSyntaxOriginDetails",
    "FlextLdifMetadataTracking",
    "FlextLdifParserMetadataBuilders",
    "FlextLdifParserRecord",
    "FlextLdifParserRecordSplitter",
    "FlextLdifParserSchemaFields",
    "FlextLdifParserValues",
    "FlextLdifServerConfig",
    "FlextLdifServerDetection",
    "FlextLdifServerTypeResolution",
    "FlextLdifServersOudUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEntryAttrsNormalization",
    "FlextLdifUtilitiesEntryDnNormalization",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesSchemaBuild",
    "FlextLdifUtilitiesSchemaExtract",
    "FlextLdifUtilitiesSchemaFormat",
    "FlextLdifUtilitiesSchemaNormalize",
    "FlextLdifUtilitiesSchemaParse",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifWriterLineFolding",
    "FlextLdifWriterRfcChars",
    "FlextLdifWriterSchemaParts",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifACLExtensionFormatting": "._acl_extensions",
        "FlextLdifACLExtraction": "._acl_extract",
        "FlextLdifACLFormatting": "._acl_format",
        "FlextLdifACLParsing": "._acl_parse",
        "FlextLdifACLPermissions": "._acl_permissions",
        "FlextLdifDNCharClass": "._dn_chars",
        "FlextLdifDNCleaning": "._dn_clean",
        "FlextLdifDNEscaping": "._dn_escape",
        "FlextLdifDNNormalization": "._dn_normalize",
        "FlextLdifDNParsing": "._dn_parse",
        "FlextLdifDNRdnParsing": "._dn_rdn",
        "FlextLdifDNRebasing": "._dn_rebase",
        "FlextLdifDNTransforming": "._dn_transform",
        "FlextLdifDNValidation": "._dn_validate",
        "FlextLdifEntryAccess": "._entry_access",
        "FlextLdifEntryAnalysis": "._entry_analysis",
        "FlextLdifEntryAttributeValidation": "._entry_attr_validation",
        "FlextLdifEntryBooleanConversion": "._entry_boolean",
        "FlextLdifEntryCriteria": "._entry_criteria",
        "FlextLdifEntryMatching": "._entry_matching",
        "FlextLdifEntryOidRfcTransforming": "._entry_oid_rfc",
        "FlextLdifEntryServerRules": "._entry_server_rules",
        "FlextLdifEntryValidation": "._entry_validation",
        "FlextLdifMetadataBuilders": "._metadata_builders",
        "FlextLdifMetadataEntryStats": "._metadata_entry_stats",
        "FlextLdifMetadataJsonCore": "._metadata_json_core",
        "FlextLdifMetadataMatchDetails": "._metadata_match",
        "FlextLdifMetadataNameDescDetails": "._metadata_name_desc",
        "FlextLdifMetadataPrefixDetails": "._metadata_prefix",
        "FlextLdifMetadataSchemaAnalysis": "._metadata_schema_analysis",
        "FlextLdifMetadataSyntaxOriginDetails": "._metadata_syntax_origin",
        "FlextLdifMetadataTracking": "._metadata_tracking",
        "FlextLdifParserMetadataBuilders": "._parser_metadata",
        "FlextLdifParserRecord": "._parser_record",
        "FlextLdifParserRecordSplitter": "._parser_records",
        "FlextLdifParserSchemaFields": "._parser_schema_fields",
        "FlextLdifParserValues": "._parser_values",
        "FlextLdifServerConfig": "._server_config",
        "FlextLdifServerDetection": "._server_detect",
        "FlextLdifServerTypeResolution": "._server_type",
        "FlextLdifServersOudUtilities": ".flext_ldif_servers_oud_utilities",
        "FlextLdifUtilitiesACL": ".acl",
        "FlextLdifUtilitiesAttribute": ".attribute",
        "FlextLdifUtilitiesCollectionLdif": ".collection_ldif",
        "FlextLdifUtilitiesDN": ".dn",
        "FlextLdifUtilitiesDispatch": ".dispatch",
        "FlextLdifUtilitiesEntry": ".entry",
        "FlextLdifUtilitiesEntryAttrsNormalization": "._transformer_attrs",
        "FlextLdifUtilitiesEntryDnNormalization": "._transformer_dn",
        "FlextLdifUtilitiesEvents": ".events",
        "FlextLdifUtilitiesMetadata": ".metadata",
        "FlextLdifUtilitiesOID": ".oid",
        "FlextLdifUtilitiesObjectClass": ".object_class",
        "FlextLdifUtilitiesParser": ".parser",
        "FlextLdifUtilitiesPipeline": ".pipeline",
        "FlextLdifUtilitiesSchema": ".schema",
        "FlextLdifUtilitiesSchemaBuild": ".schema_build",
        "FlextLdifUtilitiesSchemaExtract": ".schema_extract",
        "FlextLdifUtilitiesSchemaFormat": ".schema_format",
        "FlextLdifUtilitiesSchemaNormalize": ".schema_normalize",
        "FlextLdifUtilitiesSchemaParse": ".schema_parse",
        "FlextLdifUtilitiesServer": ".server",
        "FlextLdifUtilitiesTransformers": ".transformers",
        "FlextLdifUtilitiesValidation": ".validation",
        "FlextLdifUtilitiesWriter": ".writer",
        "FlextLdifWriterLineFolding": "._writer_fold",
        "FlextLdifWriterRfcChars": "._writer_chars",
        "FlextLdifWriterSchemaParts": "._writer_schema",
    }),
    public_exports=__all__,
)
