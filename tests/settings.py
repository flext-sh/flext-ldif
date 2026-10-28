"""Runtime settings for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsSettings

from flext_ldif import FlextLdifSettings


class TestsFlextLdifSettings(FlextLdifSettings, FlextTestsSettings):
    """LDIF settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextLdifSettings"]
