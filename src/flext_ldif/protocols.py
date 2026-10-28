# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF protocol facade.

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

from flext_cli import p as flext_cli_p

from flext_ldif._protocols import (
    FlextLdifProtocolsBase,
    FlextLdifProtocolsClient,
    FlextLdifProtocolsDomain,
    FlextLdifProtocolsLdap3,
    FlextLdifProtocolsValues,
)


class FlextLdifProtocols(flext_cli_p):
    """Unified LDIF protocol facade."""

    class Ldif(
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsBase,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsValues,
        FlextLdifProtocolsClient,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsBase`` and are inherited unchanged.
        """


p = FlextLdifProtocols
__all__: list[str] = ["FlextLdifProtocols", "p"]
