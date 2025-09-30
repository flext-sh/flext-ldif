"""Test fixtures module - Use centralized flext_tests.fixtures.

All Docker fixtures consolidated to flext_tests.fixtures.
Direct import from flext_tests - no fallback needed.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Use centralized fixtures from flext_tests (no fallback)
from flext_tests.fixtures import ldap_container as shared_ldap_container

__all__ = ["shared_ldap_container"]
