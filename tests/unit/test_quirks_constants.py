"""Tests for flext_ldif.quirks.constants module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.quirks.constants import (
    SERVER_TYPE_389DS,
    SERVER_TYPE_ACTIVE_DIRECTORY,
    SERVER_TYPE_GENERIC,
    SERVER_TYPE_OPENLDAP,
    SERVER_TYPE_ORACLE_OID,
    SERVER_TYPE_ORACLE_OUD,
    SUPPORTED_SERVER_TYPES,
)


class TestQuirksConstants:
    """Test quirks constants."""

    def test_server_type_constants(self) -> None:
        """Test server type constants."""
        assert SERVER_TYPE_OPENLDAP == "openldap"
        assert SERVER_TYPE_389DS == "389ds"
        assert SERVER_TYPE_ORACLE_OID == "oracle_oid"
        assert SERVER_TYPE_ORACLE_OUD == "oracle_oud"
        assert SERVER_TYPE_ACTIVE_DIRECTORY == "active_directory"
        assert SERVER_TYPE_GENERIC == "generic"

    def test_supported_server_types(self) -> None:
        """Test supported server types list."""
        assert len(SUPPORTED_SERVER_TYPES) == 6
        assert SERVER_TYPE_OPENLDAP in SUPPORTED_SERVER_TYPES
        assert SERVER_TYPE_ACTIVE_DIRECTORY in SUPPORTED_SERVER_TYPES
        assert SERVER_TYPE_GENERIC in SUPPORTED_SERVER_TYPES
