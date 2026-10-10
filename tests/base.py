"""Service base for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_tests import FlextTestsServiceBase

from tests import TestsFlextLdifSettings, m


class TestsFlextLdifServiceBase(FlextTestsServiceBase):
    """LDIF test service base with source and test settings namespaces."""

    @classmethod
    @override
    def fetch_settings(cls) -> TestsFlextLdifSettings:
        """Return the typed LDIF+CLI+Tests settings singleton for test services."""
        resolved = super().fetch_settings()
        if isinstance(resolved, TestsFlextLdifSettings):
            return resolved
        return TestsFlextLdifSettings.model_validate(resolved)

    @classmethod
    @override
    def runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextLdifSettings)


s = TestsFlextLdifServiceBase

__all__: list[str] = ["TestsFlextLdifServiceBase", "s"]
