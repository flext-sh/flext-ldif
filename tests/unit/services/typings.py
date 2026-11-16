"""Service test typings for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
tests/unit/services/typings
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import p


class TestsFlextLdifTypingsService:
    """Service test typings namespace."""

    type ServerClass = type[p.Ldif.SchemaServer]


__all__: list[str] = ["TestsFlextLdifTypingsService"]
