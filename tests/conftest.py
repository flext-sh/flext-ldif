"""Pytest plugin routing for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

pytest_plugins = ["tests.unit.fixtures", "tests.integration.fixtures"]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """LDIF-only integration stays active; LDAP fixture consumers are gated."""
    for item in items:
        if "ldap_container" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.docker)
            item.add_marker(pytest.mark.ldap)
