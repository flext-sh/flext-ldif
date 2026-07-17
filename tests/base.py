"""Service base for flext-ldif tests."""

from __future__ import annotations

from typing import override

from flext_tests import s as tests_s

from flext_ldif import m, p
from tests.settings import TestsFlextLdifSettings


class TestsFlextLdifServiceBase(tests_s):
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
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextLdifSettings)


s = TestsFlextLdifServiceBase

__all__: list[str] = ["TestsFlextLdifServiceBase", "s"]
