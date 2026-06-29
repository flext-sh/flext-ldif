"""Integration tests for OUD to OID migration.

Tests complete migration workflow from Oracle Unified Directory (OUD) to
Oracle Internet Directory (OID) using servers system:
- Read OUD LDIF fixtures with OUD servers
- Convert to RFC intermediate format
- Convert from RFC to OID format with OID servers
- Write OID LDIF
- Validate migration integrity and data preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from tests.constants import c
from tests.utilities import TestsFlextLdifUtilities as u


class TestsFlextLdifOudToOidMigration:
    """Test OUD to OID schema migration."""

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD schema server instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID schema server instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oud_schema_fixture(self) -> str:
        """Load OUD schema fixture data."""
        fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)
        return fixture_content

    """Test OUD to OID ACL migration."""

    @pytest.fixture
    def oud_acl(self) -> FlextLdifServersOud.Acl:
        """Create OUD ACL server instance."""
        return FlextLdifServersOud.Acl()

    @pytest.fixture
    def oid_acl(self) -> FlextLdifServersOid.Acl:
        """Create OID ACL server instance."""
        return FlextLdifServersOid.Acl()

    """Test OUD to OID entry migration."""

    @pytest.fixture
    def oud_entry(self) -> FlextLdifServersOud.Entry:
        """Create OUD entry server instance."""
        return FlextLdifServersOud.Entry()

    """Test complete OUD to OID migration workflow."""

    @pytest.fixture
    def oud_fixtures(self) -> str:
        """Create OUD entries fixture data."""
        fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
        return fixture_content

    @pytest.fixture
    def oid_entry(self) -> FlextLdifServersOid.Entry:
        """Create OID entry server."""
        return FlextLdifServersOid.Entry()


__all__: list[str] = [
    "TestsFlextLdifOudToOidMigration",
]
