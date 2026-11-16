# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Parser package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._parser.metadata import FlextLdifUtilitiesParserMetadata
    from flext_ldif._utilities._parser.record import FlextLdifUtilitiesParserRecord
    from flext_ldif._utilities._parser.records import FlextLdifUtilitiesParserRecords
    from flext_ldif._utilities._parser.schema_fields import (
        FlextLdifUtilitiesParserSchemaFields,
    )
    from flext_ldif._utilities._parser.values import FlextLdifUtilitiesParserValues


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesParserMetadata",
    "FlextLdifUtilitiesParserRecord",
    "FlextLdifUtilitiesParserRecords",
    "FlextLdifUtilitiesParserSchemaFields",
    "FlextLdifUtilitiesParserValues",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesParserMetadata": ".metadata",
        "FlextLdifUtilitiesParserRecord": ".record",
        "FlextLdifUtilitiesParserRecords": ".records",
        "FlextLdifUtilitiesParserSchemaFields": ".schema_fields",
        "FlextLdifUtilitiesParserValues": ".values",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesParserMetadata": (
            "_as_str_list",
            "_strict_str_list_view",
            "ext",
            "build_rfc_entry_metadata",
            "_build_attribute_metadata",
        ),
        "FlextLdifUtilitiesParserRecord": (
            "_MODIFY_OPS",
            "_RecordState",
            "_DecodedValue",
            "finalize_change_operation",
            "_handle_changetype_line",
            "_apply_moddn_field",
            "_apply_modify_field",
            "_store_attribute",
            "_apply_special_line",
            "_parse_data_line",
            "_build_entry",
            "parse_ldif_record",
        ),
        "FlextLdifUtilitiesParserRecords": (
            "unfold_numbered_lines",
            "unfold_lines",
            "split_numbered_records",
            "split_ldif_records",
        ),
        "FlextLdifUtilitiesParserSchemaFields": (
            "extract_oid",
            "extract_optional_field",
            "extract_boolean_flag",
            "extract_extensions",
        ),
        "FlextLdifUtilitiesParserValues": (
            "decode_value",
            "build_control",
            "parse_attribute_line",
        ),
    },
)
