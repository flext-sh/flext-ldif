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
    FlextLdifConstantsEnums,
    FlextLdifConstantsServers,
    FlextLdifConstantsServersBase,
    FlextLdifConstantsServersOid,
    FlextLdifConstantsServersOud,
    FlextLdifConstantsServersRelaxed,
    FlextLdifConstantsServersRfc,
)
from flext_ldif._constants.str_enums import FlextLdifConstantsStrEnums


class FlextLdifConstants(FlextCliConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsBase,
        FlextLdifConstantsEnums,
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsAclConvertOud,
        FlextLdifConstantsServers,
        FlextLdifConstantsServersBase,
        FlextLdifConstantsServersRfc,
        FlextLdifConstantsServersOid,
        FlextLdifConstantsServersOud,
        FlextLdifConstantsServersRelaxed,
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
