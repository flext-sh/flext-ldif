"""LDIF constants and enumerations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique

from flext_cli import FlextCliConstants

from flext_ldif._constants import (
    FlextLdifConstantsAclConvert,
    FlextLdifConstantsAclConvertOud,
    FlextLdifConstantsBase,
    FlextLdifConstantsEnums,
)


class FlextLdifConstants(FlextCliConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsBase,
        FlextLdifConstantsEnums,
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsAclConvertOud,
    ):
        """LDIF domain constants namespace."""

        @unique
        class EntryCriteriaMode(StrEnum):
            """Matching strategy for entry criteria evaluation."""

            ANY = "any"
            ALL = "all"

        @unique
        class SchemaItemKind(StrEnum):
            """Schema item discriminator used in conversion flows."""

            ATTRIBUTE = "attribute"
            OBJECTCLASS = "objectclass"

        @unique
        class NormalizeFallback(StrEnum):
            """Fallback strategy when DN normalization fails."""

            LOWER = "lower"
            UPPER = "upper"
            ORIGINAL = "original"

        # OperationalAttributes.IGNORE_SET is owned by
        # ``FlextLdifConstantsBase`` in ``_constants/base.py`` (ENFORCE-079)
        # and resolves through the MRO.

        @unique
        class LogLevelLower(StrEnum):
            """Lowercase log-level names for logger dispatch comparisons."""

            DEBUG = "debug"
            INFO = "info"
            WARNING = "warning"
            ERROR = "error"
            CRITICAL = "critical"


c = FlextLdifConstants

__all__: list[str] = ["FlextLdifConstants", "c"]
