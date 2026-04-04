"""Protocol definitions for flext-ldif tests.

Provides FlextLdifTestProtocols, extending FlextTestsProtocols with flext-ldif-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldap import FlextLdapProtocols
from flext_tests import FlextTestsProtocols


class FlextLdifTestProtocols(
    FlextTestsProtocols,
    FlextLdapProtocols,
):
    """Protocol definitions for flext-ldif tests.

    Extends both FlextTestsProtocols and FlextLdifProtocols with flext-ldif-specific
    protocol definitions.

    Provides access to:
    - FlextTestsProtocols.Tests.Docker.* (from FlextTestsProtocols)
    - FlextTestsProtocols.Tests.Factory.* (from FlextTestsProtocols)
    - FlextLdifProtocols.Ldif.* (from FlextLdifProtocols)

    Rules:
    - NEVER redeclare protocols from parent classes
    - Only flext-ldif-specific test protocols allowed
    """

    class Ldif(FlextLdapProtocols.Ldif):
        """Flext-ldif-specific test protocols."""

        class Tests:
            """Project-specific test protocols for flext-ldif.

            Separated from FlextTestsProtocols.Tests to avoid bad-override.
            Access via p.Ldif.Tests.* for flext-ldif-specific protocols.
            """

            @runtime_checkable
            class LdapConnectionLike(Protocol):
                """Typed ldap3 connection contract used by test helpers."""

                bound: bool

                def unbind(self) -> bool:
                    """Close the LDAP connection."""
                    ...


p = FlextLdifTestProtocols

__all__ = ["FlextLdifTestProtocols", "p"]
