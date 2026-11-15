# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Writer package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._writer.chars import FlextLdifUtilitiesWriterChars
    from flext_ldif._utilities._writer.fold import FlextLdifUtilitiesWriterFold
    from flext_ldif._utilities._writer.schema import FlextLdifUtilitiesWriterSchema


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesWriterChars",
    "FlextLdifUtilitiesWriterFold",
    "FlextLdifUtilitiesWriterSchema",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesWriterChars": ".chars",
        "FlextLdifUtilitiesWriterFold": ".fold",
        "FlextLdifUtilitiesWriterSchema": ".schema",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesWriterChars": ("needs_base64_encoding",),
        "FlextLdifUtilitiesWriterFold": (
            "Fold",
            "_initial_chunk_end",
            "_decode_chunk",
            "_keyword_prefix_end",
            "_initial_split_index",
            "_adjust_split_for_keyword_token",
            "_prefer_whitespace_split",
            "fold_line",
            "_aci_layout_fold_points",
            "fold_aci_layout",
        ),
        "FlextLdifUtilitiesWriterSchema": (
            "add_attribute_flags",
            "add_attribute_matching_rules",
            "add_attribute_syntax",
            "finalize_ldif_text",
        ),
    },
)
