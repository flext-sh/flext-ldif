"""Oracle Unified Directory (OUD) Servers.

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

from flext_ldif._constants.servers_oud import FlextLdifConstantsServersOud
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc


class FlextLdifConstantsServersOud(
    FlextLdifConstantsServersOud,
    FlextLdifConstantsServersRfc,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersOud"]
