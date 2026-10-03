"""Pytest plugin routing for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

pytest_plugins = ["tests.unit.fixtures", "tests.integration.fixtures"]
