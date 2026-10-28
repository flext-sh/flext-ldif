# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF constants and enumerations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_cli import c as flext_cli_c

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


class FlextLdifConstants(flext_cli_c):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsBase,
        FlextLdifConstantsBaseParts,
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


c = FlextLdifConstants
__all__: list[str] = ["FlextLdifConstants", "c"]
