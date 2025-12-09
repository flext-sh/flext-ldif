"""Tests for quirks manager and quirks lifecycle management.

This module tests the QuirksManager that handles discovery, registration,
and lifecycle management of server-specific quirks implementations.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest

from flext_ldif.constants import c as lib_c
from flext_ldif.services.server import FlextLdifServer
from tests import s


# Test scenario enums
class ServerType(StrEnum):
    """Server types for quirks management testing."""

    ORACLE_OID = "oracle_oid"
    ORACLE_OUD = "oracle_oud"
    OPENLDAP_1 = "openldap_1"
    ACTIVE_DIRECTORY = "active_directory"
    APACHE_DIRECTORY = "apache_directory"
    DS_389 = "ds_389"
    NOVELL_EDIRECTORY = "novell_edirectory"
    IBM_TIVOLI = "ibm_tivoli"
    GENERIC = "generic"


class QuirkType(StrEnum):
    """Quirk types for testing."""

    SCHEMA = "schema"
    ACL = "acl"
    ENTRY = "entry"


# Test data structures
@dataclasses.dataclass(frozen=True)
class QuirkTestCase:
    """Quirk retrieval test case."""

    server_type: str
    quirk_type: str
    should_exist: bool = True


# Test data mappings
SCHEMA_QUIRK_TESTS = [
    QuirkTestCase(lib_c.Ldif.ServerTypes.OID, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OUD, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OPENLDAP1, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.AD, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.APACHE, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.DS389, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.NOVELL, QuirkType.SCHEMA),
    QuirkTestCase(lib_c.Ldif.ServerTypes.IBM_TIVOLI, QuirkType.SCHEMA),
]

ACL_QUIRK_TESTS = [
    QuirkTestCase(lib_c.Ldif.ServerTypes.OID, QuirkType.ACL),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OUD, QuirkType.ACL),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OPENLDAP1, QuirkType.ACL),
    # Note: Some servers may have ACL quirks or not, we just verify retrieval works
]

ENTRY_QUIRK_TESTS = [
    QuirkTestCase(lib_c.Ldif.ServerTypes.OID, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OUD, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.OPENLDAP1, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.AD, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.APACHE, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.DS389, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.NOVELL, QuirkType.ENTRY),
    QuirkTestCase(lib_c.Ldif.ServerTypes.IBM_TIVOLI, QuirkType.ENTRY),
]

ALL_SUPPORTED_SERVERS = [
    lib_c.Ldif.ServerTypes.OPENLDAP1,
    lib_c.Ldif.ServerTypes.OID,
    lib_c.Ldif.ServerTypes.OUD,
    lib_c.Ldif.ServerTypes.AD,
    lib_c.Ldif.ServerTypes.APACHE,
    lib_c.Ldif.ServerTypes.DS389,
    lib_c.Ldif.ServerTypes.NOVELL,
    lib_c.Ldif.ServerTypes.IBM_TIVOLI,
]


# Parametrization functions
def get_schema_quirk_cases() -> list[QuirkTestCase]:
    """Generate schema quirk test cases."""
    return SCHEMA_QUIRK_TESTS


def get_acl_quirk_cases() -> list[QuirkTestCase]:
    """Generate ACL quirk test cases."""
    return ACL_QUIRK_TESTS


def get_entry_quirk_cases() -> list[QuirkTestCase]:
    """Generate entry quirk test cases."""
    return ENTRY_QUIRK_TESTS


def get_all_server_types() -> list[str]:
    """Generate all supported server types."""
    return ALL_SUPPORTED_SERVERS


# Module-level fixtures
@pytest.fixture
def registry() -> FlextLdifServer:
    """Create FlextLdifServer registry instance."""
    return FlextLdifServer()


# Test classes
class TestsTestFlextLdifServerInitialization(s):
    """Test FlextLdifServer initialization and singleton behavior."""

    def test_initialization(self, registry: FlextLdifServer) -> None:
        """Test registry initialization."""
        assert registry is not None
        assert isinstance(registry, FlextLdifServer)

    def test_get_global_instance(self) -> None:
        """Test getting global singleton registry instance."""
        registry1 = FlextLdifServer.get_global_instance()
        registry2 = FlextLdifServer.get_global_instance()

        assert registry1 is not None
        assert registry2 is not None
        assert isinstance(registry1, FlextLdifServer)
        assert isinstance(registry2, FlextLdifServer)
        # Both should be the same instance (singleton)
        assert registry1 is registry2


class TestFlextLdifServerQuirkRetrieval:
    """Test retrieval of quirks by server type."""

    @pytest.mark.parametrize("test_case", get_schema_quirk_cases())
    def test_get_schema_quirks(
        self,
        registry: FlextLdifServer,
        test_case: QuirkTestCase,
    ) -> None:
        """Test getting schema quirks for supported servers."""
        quirk = registry.schema(test_case.server_type)
        assert quirk is not None, f"Schema quirk not found for {test_case.server_type}"

    @pytest.mark.parametrize("test_case", get_acl_quirk_cases())
    def test_get_acl_quirks(
        self,
        registry: FlextLdifServer,
        test_case: QuirkTestCase,
    ) -> None:
        """Test getting ACL quirks for supported servers."""
        quirk = registry.acl(test_case.server_type)
        assert quirk is not None, f"ACL quirk not found for {test_case.server_type}"

    @pytest.mark.parametrize("test_case", get_entry_quirk_cases())
    def test_get_entry_quirks(
        self,
        registry: FlextLdifServer,
        test_case: QuirkTestCase,
    ) -> None:
        """Test getting entry quirks for supported servers."""
        quirk = registry.entry(test_case.server_type)
        assert quirk is not None, f"Entry quirk not found for {test_case.server_type}"


class TestFlextLdifServerRegistryCompletion:
    """Test registry completeness for all supported server types."""

    @pytest.mark.parametrize("server_type", get_all_server_types())
    def test_registry_supports_all_server_types(
        self,
        registry: FlextLdifServer,
        server_type: str,
    ) -> None:
        """Test that registry has quirks for all supported server types."""
        # Test schema quirks
        schema = registry.schema(server_type)
        assert schema is not None, f"Schema quirk not found for {server_type}"

        # Test entry quirks
        entry = registry.entry(server_type)
        assert entry is not None, f"Entry quirk not found for {server_type}"

        # Test ACL quirks (may be None for some servers, but retrieval should work)
        # ACL may be None for some servers - this is acceptable
        registry.acl(server_type)


__all__ = [
    "QuirkTestCase",
    "QuirkType",
    "ServerType",
    "TestFlextLdifServerInitialization",
    "TestFlextLdifServerQuirkRetrieval",
    "TestFlextLdifServerRegistryCompletion",
]
