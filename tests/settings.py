"""Runtime settings for flext-ldif tests."""

from __future__ import annotations

from flext_ldif import FlextLdifSettings
from flext_tests import FlextTestsSettings


class TestsFlextLdifSettings(FlextLdifSettings, FlextTestsSettings):
    """LDIF settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextLdifSettings"]
