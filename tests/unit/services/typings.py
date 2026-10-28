"""Service test typings for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
tests/unit/services/typings
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

from flext_ldif.servers import (
    FlextLdifServersOid,
    FlextLdifServersOud,
    FlextLdifServersRfc,
)


class TestsFlextLdifTypingsService:
    """Service test typings namespace."""

    type ServerClass = type[
        FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud
    ]


__all__: list[str] = ["TestsFlextLdifTypingsService"]
