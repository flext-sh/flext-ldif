"""Baseline server-profile constants shared by every family.

ENFORCE-079 part module: declarations live in the
_constants package; the server constants classes compose them via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_ldif._constants import FlextLdifConstantsBase

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifConstantsServersBase:
    """Baseline server-profile constants shared by every family."""

    SERVER_TYPE: ClassVar[str]

    PRIORITY: ClassVar[int]

    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset()

    ACL_FORMAT: ClassVar[str] = ""

    ACL_ATTRIBUTE_NAME: ClassVar[str] = ""

    SCHEMA_DN: ClassVar[str] = ""

    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"

    RFC_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        FlextLdifConstantsBase.RFC_ACL_ATTRIBUTES
    )

    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset()

    ATTRIBUTE_ALIASES: ClassVar[t.StrSequenceMapping] = MappingProxyType({})

    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()

    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({})

    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = ()

    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({})

    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset()

    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    DETECTION_PATTERN: ClassVar[str] = ""

    DETECTION_WEIGHT: ClassVar[int] = 0

    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    DETECTION_OID_PATTERN: ClassVar[str] = ""

    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()

    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()

    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()

    CANONICAL_NAME: ClassVar[str] = ""

    ALIASES: ClassVar[frozenset[str]] = frozenset()

    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset()
