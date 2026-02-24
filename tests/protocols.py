"""Protocol definitions for flext-ldif tests.

Provides TestsFlextLdifProtocols, extending FlextTestsProtocols with flext-ldif-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.protocols import FlextLdifProtocols
from flext_tests.protocols import FlextTestsProtocols


class TestsFlextLdifProtocols(FlextTestsProtocols, FlextLdifProtocols):
    """Protocol definitions for flext-ldif tests.

    Extends both FlextTestsProtocols and FlextLdifProtocols with flext-ldif-specific
    protocol definitions.

    Provides access to:
    - tp.Tests.Docker.* (from FlextTestsProtocols)
    - tp.Tests.Factory.* (from FlextTestsProtocols)
    - tp.Ldif.* (from FlextLdifProtocols)

    Rules:
    - NEVER redeclare protocols from parent classes
    - Only flext-ldif-specific test protocols allowed
    """

    class Tests:
        """Project-specific test protocols.

        Extends FlextTestsProtocols.Tests with flext-ldif-specific protocols.
        """

        class Ldif:
            """Flext-ldif-specific test protocols."""


# Runtime aliases
p = TestsFlextLdifProtocols

__all__ = [
    "TestsFlextLdifProtocols",
    "p",
]
