# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Typings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._typings.base import FlextLdifTypesBase
    from flext_ldif._typings.domain import FlextLdifTypesDomain


__all__: tuple[str, ...] = ("FlextLdifTypesBase", "FlextLdifTypesDomain")

install_lazy_exports(
    __name__,
    globals(),
    {"FlextLdifTypesBase": ".base", "FlextLdifTypesDomain": ".domain"},
    public_exports=__all__,
    deferred_members={
        "FlextLdifTypesBase": (
            "_coerce_normalized_str_frozenset",
            "RegexPattern",
            "RegexMatch",
            "Scalar",
            "MetadataInputValue",
            "MetadataInputMapping",
            "MutableMetadataInputMapping",
            "MutableMetadataMapping",
            "MetadataCarrierValue",
            "MetadataAnalysisDetail",
            "ValueType",
            "AttributeValue",
            "MutableEntryAttributesDict",
            "UnconvertedAttributeValue",
            "UnconvertedAttributes",
            "SchemaExtensionsMapping",
            "AttributeDict",
            "DN",
            "ParseMethodArg",
            "ParseMethodReturn",
            "WriteMethodArg",
            "WriteMethodReturn",
            "Rfc4512Descriptor",
            "Rfc4514DnComponent",
            "Rfc2849AttributeValue",
            "NormalizedStrFrozenset",
        ),
        "FlextLdifTypesDomain": (
            "AclPayload",
            "EntryPayload",
            "EntryLike",
            "EntrySequence",
            "EntryOrEntries",
            "SchemaAttributeLike",
            "SchemaObjectClassLike",
            "SchemaItem",
            "AclLike",
            "AclAttributeNames",
            "AclSequence",
            "ConvertedModel",
            "SchemaConversionValue",
            "EventType",
            "ResponseLike",
            "ParseResponseLike",
            "ValidationResultLike",
            "MigrationPipelineResultLike",
            "WriteResponseLike",
            "ServerServerLike",
            "AclBrowsePlacement",
        ),
    },
)
