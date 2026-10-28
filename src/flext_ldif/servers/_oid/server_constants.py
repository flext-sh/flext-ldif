"""Oracle Internet Directory (OID) Servers.

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

from flext_ldif._constants.servers_oid import FlextLdifConstantsServersOid
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc


class FlextLdifConstantsServersOid(
    FlextLdifConstantsServersOid,
    FlextLdifConstantsServersRfc,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersOid"]
