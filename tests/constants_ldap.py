"""ldap3 wire constants consumed by the real-directory tests.

Focused constants module split out of ``tests.constants``; the public surface
is re-exported through ``tests.constants`` (see ``TestsFlextLdifConstantsLdap``).

flext-ldif is the base library of the LDAP client, so the client cannot be a
declared dependency here (see ``tests.utilities``). These are the ldap3
protocol values the tests pass to the dynamically resolved client, not a
second implementation of an owned facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique


class TestsFlextLdifConstantsLdap:
    """ldap3 wire constants consumed by the real-directory tests."""

    @unique
    class Ldap3SearchScope(StrEnum):
        """ldap3-compatible search scope string values."""

        BASE = "BASE"
        LEVEL = "LEVEL"
        SUBTREE = "SUBTREE"

    @unique
    class Ldap3GetInfo(StrEnum):
        """ldap3-compatible get-info option string values."""

        ALL = "ALL"
        DSA = "DSA"
        NO_INFO = "NO_INFO"
        SCHEMA = "SCHEMA"


__all__: list[str] = ["TestsFlextLdifConstantsLdap"]
