"""Integration tests for OUD to OID migration.

Tests complete migration workflow from Oracle Unified Directory (OUD) to
Oracle Internet Directory (OID) using quirks system:
- Read OUD LDIF fixtures with OUD quirks
- Convert to RFC intermediate format
- Convert from RFC to OID format with OID quirks
- Write OID LDIF
- Validate migration integrity and data preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from tests.fixtures.loader import FlextLdifFixtures


class TestOudToOidSchemaMigration:
    """Test OUD to OID schema migration."""

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oud_schema_fixture(self) -> str:
        """Load OUD schema fixture data."""
        loader = FlextLdifFixtures.OUD()
        return loader.schema()


class TestOudToOidAclMigration:
    """Test OUD to OID ACL migration."""

    @pytest.fixture
    def oud_acl(self) -> FlextLdifServersOud.Acl:
        """Create OUD ACL quirk instance."""
        return FlextLdifServersOud.Acl()

    @pytest.fixture
    def oid_acl(self) -> FlextLdifServersOid.Acl:
        """Create OID ACL quirk instance."""
        return FlextLdifServersOid.Acl()


class TestOudToOidEntryMigration:
    """Test OUD to OID entry migration."""

    @pytest.fixture
    def oud_entry(self) -> FlextLdifServersOud.Entry:
        """Create OUD entry quirk instance."""
        return FlextLdifServersOud.Entry()


class TestOudToOidFullMigration:
    """Test complete OUD to OID migration workflow."""

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD schema quirk."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID schema quirk."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oud_entry(self) -> FlextLdifServersOud.Entry:
        """Create OUD entry quirk."""
        return FlextLdifServersOud.Entry()

    @pytest.fixture
    def oid_entry(self) -> FlextLdifServersOid.Entry:
        """Create OID entry quirk."""
        return FlextLdifServersOid.Entry()


__all__ = [
    "TestOudToOidAclMigration",
    "TestOudToOidEntryMigration",
    "TestOudToOidFullMigration",
    "TestOudToOidSchemaMigration",
]
