"""Protocol definitions for flext-ldif tests.

Provides TestsFlextLdifProtocols, extending TestsFlextProtocols with flext-ldif-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldap import FlextLdapProtocols
from flext_tests import FlextTestsProtocols


class TestsFlextLdifProtocols(
    FlextTestsProtocols,
    FlextLdapProtocols,
):
    """Protocol definitions for flext-ldif tests."""

    class Ldif(FlextLdapProtocols.Ldif):
        """Flext-ldif-specific test protocols."""

        class Tests:
            """Project-specific test protocols for flext-ldif."""

            @runtime_checkable
            class LdapConnectionLike(Protocol):
                """Typed ldap3 connection contract used by test helpers."""

                bound: bool

                def unbind(self) -> bool:
                    """Close the LDAP connection."""
                    ...


p = TestsFlextLdifProtocols

__all__ = ["TestsFlextLdifProtocols", "p"]
