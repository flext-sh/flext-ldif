# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF constants and enumerations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_cli import FlextCliConstants

from flext_ldif._constants import (
    FlextLdifConstantsAclConvert,
    FlextLdifConstantsAclConvertOud,
    FlextLdifConstantsBase,
    FlextLdifConstantsBaseParts,
    FlextLdifConstantsEnums,
    FlextLdifConstantsServers,
    FlextLdifConstantsServersBase,
    FlextLdifConstantsServersOid,
    FlextLdifConstantsServersOud,
    FlextLdifConstantsServersRelaxed,
    FlextLdifConstantsServersRfc,
    FlextLdifConstantsStrEnums,
)


class FlextLdifConstants(FlextCliConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsBaseParts,
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsBase,
        FlextLdifConstantsServers,
        FlextLdifConstantsServersBase,
        FlextLdifConstantsServersOid,
        FlextLdifConstantsServersOud,
        FlextLdifConstantsServersRelaxed,
        FlextLdifConstantsServersRfc,
        FlextLdifConstantsStrEnums,
        FlextLdifConstantsEnums,
        FlextLdifConstantsAclConvertOud,
    ):
        """LDIF domain constants namespace."""

        SchemaItemKind: ClassVar[type[FlextLdifConstantsStrEnums.SchemaItemKind]] = (
            FlextLdifConstantsStrEnums.SchemaItemKind
        )

        NormalizeFallback = FlextLdifConstantsStrEnums.NormalizeFallback

        # OperationalAttributes.IGNORE_SET is owned by
        # ``FlextLdifConstantsBase`` in ``_constants/base.py`` (ENFORCE-079)
        # and resolves through the MRO.

        LogLevelLower = FlextLdifConstantsStrEnums.LogLevelLower


c = FlextLdifConstants

__all__: list[str] = ["FlextLdifConstants", "c"]
