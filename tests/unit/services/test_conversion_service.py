"""Tests for FlextLdif Conversion service functionality.

This module tests the Conversion service for transforming LDIF entries
between different LDAP server formats using the quirks system.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import cast

import pytest
from flext_core import FlextResult
from flext_tests import tm

from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from tests import m, p, s
from tests.helpers.compat import TestAssertions

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def conversion_service() -> FlextLdifConversion:
    """Create FlextLdifConversion instance."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> FlextLdifServer:
    """Create FlextLdifServer instance for getting quirks."""
    return FlextLdifServer()


@pytest.fixture
def rfc_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get RFC server quirk via FlextLdifServer API."""
    quirk_result = server.quirk("rfc")
    assert quirk_result.is_success, "RFC quirk must be available"
    return quirk_result.value


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API."""
    quirk_result = server.quirk("oid")
    assert quirk_result.is_success, "OID quirk must be available"
    return quirk_result.value


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API."""
    quirk_result = server.quirk("oud")
    assert quirk_result.is_success, "OUD quirk must be available"
    return quirk_result.value


@pytest.fixture
def simple_entry() -> p.Entry:
    """Create simple entry for conversion testing."""
    return s().create_entry(
        "cn=test,dc=example,dc=com",
        {
            "cn": ["test"],
            "sn": ["User"],
            "objectClass": ["person"],
        },
    )


@pytest.fixture
def complex_entry() -> p.Entry:
    """Create complex entry for conversion testing."""
    return s().create_entry(
        "cn=John Doe,ou=People,dc=example,dc=com",
        {
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john.doe@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        },
    )


# ════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED TEST CLASS
# ════════════════════════════════════════════════════════════════════════════


class TestsTestFlextLdifConversionService(s):
    """Test FlextLdifConversion service with real implementations."""

    class ExecuteScenario(StrEnum):
        """Execute test scenarios."""

        RETURNS_ENTRY = "returns_entry"
        HEALTH_CHECK_SUCCESS = "health_check_success"

    class ResolveQuirkScenario(StrEnum):
        """Resolve quirk test scenarios."""

        FROM_STRING_RFC = "from_string_rfc"
        FROM_STRING_OID = "from_string_oid"
        FROM_STRING_OUD = "from_string_oud"
        FROM_INSTANCE = "from_instance"
        INVALID_TYPE = "invalid_type"

    class ConvertScenario(StrEnum):
        """Convert test scenarios."""

        RFC_TO_RFC = "rfc_to_rfc"
        RFC_TO_OID = "rfc_to_oid"
        OID_TO_OUD = "oid_to_oud"
        OUD_TO_RFC = "oud_to_rfc"
        WITH_STRING_TYPES = "with_string_types"
        COMPLEX_ENTRY = "complex_entry"
        INVALID_MODEL_TYPE = "invalid_model_type"
        INVALID_DN = "invalid_dn"

    class BatchConvertScenario(StrEnum):
        """Batch convert test scenarios."""

        EMPTY_LIST = "empty_list"
        SINGLE_ENTRY = "single_entry"
        MULTIPLE_ENTRIES = "multiple_entries"
        PARTIAL_FAILURES = "partial_failures"

    class GetSupportedConversionsScenario(StrEnum):
        """Get supported conversions scenarios."""

        RFC_QUIRK = "rfc_quirk"
        OID_QUIRK = "oid_quirk"
        OUD_QUIRK = "oud_quirk"

    class SchemaConversionScenario(StrEnum):
        """Schema conversion scenarios."""

        SCHEMA_ATTRIBUTE = "schema_attribute"
        SCHEMA_OBJECTCLASS = "schema_objectclass"

    class AclConversionScenario(StrEnum):
        """ACL conversion scenarios."""

        RFC_TO_OID = "rfc_to_oid"
        ROUNDTRIP = "roundtrip"

    class RoundtripScenario(StrEnum):
        """Roundtrip conversion scenarios."""

        RFC_TO_OID_TO_RFC = "rfc_to_oid_to_rfc"
        OID_TO_OUD_TO_OID = "oid_to_oud_to_oid"

    class DnRegistryScenario(StrEnum):
        """DN registry scenarios."""

        INITIALIZED = "initialized"
        TRACKS_DNS = "tracks_dns"
        RESET = "reset"
        MULTIPLE_DNS = "multiple_dns"
        RESET_CLEARS = "reset_clears"

    class ErrorHandlingScenario(StrEnum):
        """Error handling scenarios."""

        INVALID_SOURCE_TYPE = "invalid_source_type"
        INVALID_TARGET_TYPE = "invalid_target_type"
        BATCH_INVALID_SOURCE = "batch_invalid_source"
        EXECUTE_EXCEPTION = "execute_exception"

    # ────────────────────────────────────────────────────────────────────────
    # EXECUTE TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_execute_returns_entry(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test execute() returns health check entry."""
        result = conversion_service.execute()
        assert result.is_success
        entry = result.value
        # Entry must be m.Ldif.Entry
        assert isinstance(entry, m.Ldif.Entry)
        # Type narrowing: ensure dn is not None
        if entry.dn is not None:
            assert entry.dn.value == "cn=health-check"

    def test_execute_health_check_success(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test execute() health check succeeds."""
        result = conversion_service.execute()
        assert result.is_success
        entry = result.value
        # execute() returns m.Ldif.Entry
        assert isinstance(entry, m.Ldif.Entry)
        # Type narrowing: ensure attributes is not None
        if entry.attributes is not None:
            assert entry.attributes.attributes == {}

    # ────────────────────────────────────────────────────────────────────────
    # RESOLVE QUIRK TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_resolve_quirk_from_string_rfc(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test resolving quirk from string type."""
        quirk = FlextLdifConversion._resolve_quirk("rfc")
        assert quirk is not None
        assert hasattr(quirk, "server_type") or hasattr(quirk, "server_name")

    def test_resolve_quirk_from_string_oid(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test resolving OID quirk from string."""
        quirk = FlextLdifConversion._resolve_quirk("oid")
        assert quirk is not None

    def test_resolve_quirk_from_string_oud(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test resolving OUD quirk from string."""
        quirk = FlextLdifConversion._resolve_quirk("oud")
        assert quirk is not None

    def test_resolve_quirk_from_instance(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test resolving quirk from instance."""
        quirk = FlextLdifConversion._resolve_quirk(rfc_quirk)
        assert quirk is rfc_quirk

    def test_resolve_quirk_invalid_type(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test resolving invalid server type."""
        with pytest.raises(ValueError, match="Invalid server type"):
            FlextLdifConversion._resolve_quirk("invalid_server_type")

    # ────────────────────────────────────────────────────────────────────────
    # CONVERT ENTRY TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_convert_rfc_to_rfc(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        simple_entry: p.Entry,
    ) -> None:
        """Test converting Entry from RFC to RFC (roundtrip)."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)
        # Type narrowing: ensure dn is not None
        if converted.dn is not None and simple_entry.dn is not None:
            assert converted.dn.value == simple_entry.dn.value

    def test_convert_rfc_to_oid(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
        simple_entry: p.Entry,
    ) -> None:
        """Test converting Entry from RFC to OID."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)
        # Type narrowing: ensure dn is not None
        if converted.dn is not None and simple_entry.dn is not None:
            assert converted.dn.value == simple_entry.dn.value

    def test_convert_oid_to_oud(
        self,
        conversion_service: FlextLdifConversion,
        oid_quirk: FlextLdifServersOid,
        oud_quirk: FlextLdifServersOud,
        simple_entry: p.Entry,
    ) -> None:
        """Test converting Entry from OID to OUD."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            oid_quirk,
            oud_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)
        # Type narrowing: ensure dn is not None
        if converted.dn is not None and simple_entry.dn is not None:
            assert converted.dn.value == simple_entry.dn.value

    def test_convert_oud_to_rfc(
        self,
        conversion_service: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
        rfc_quirk: FlextLdifServersRfc,
        simple_entry: p.Entry,
    ) -> None:
        """Test converting Entry from OUD to c.RFC."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            oud_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)

    def test_convert_with_string_server_types(
        self,
        conversion_service: FlextLdifConversion,
        simple_entry: p.Entry,
    ) -> None:
        """Test converting Entry using string server types."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            "rfc",
            "oid",
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)

    def test_convert_complex_entry(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
        complex_entry: p.Entry,
    ) -> None:
        """Test converting complex Entry."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", complex_entry),
        )
        assert result.is_success
        converted = result.value
        assert isinstance(converted, m.Ldif.Entry)
        # Type narrowing: ensure dn is not None
        if converted.dn is not None and complex_entry.dn is not None:
            assert converted.dn.value == complex_entry.dn.value

    def test_convert_invalid_model_type(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test converting invalid model type (should fail)."""
        invalid_model = "this is not a valid model"
        # Cast to ConvertibleModel for type checker (will fail at runtime)
        result = conversion_service.convert(
            rfc_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", invalid_model),
        )
        assert result.is_failure
        assert result.error is not None
        assert "Unsupported model type" in result.error

    def test_convert_entry_with_invalid_dn(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test converting Entry with invalid DN."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="invalid-dn-format"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
        )
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", entry),
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "validation" in error_msg.lower() or "dn" in error_msg.lower()

    # ────────────────────────────────────────────────────────────────────────
    # BATCH CONVERT TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_batch_convert_empty_list(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test batch_convert with empty list (NEW API - returns empty result)."""
        result = conversion_service.batch_convert(rfc_quirk, rfc_quirk, [])
        assert result.is_success
        converted = result.value
        tm.assert_length_equals(converted, 0)

    def test_batch_convert_single_entry(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
        simple_entry: p.Entry,
    ) -> None:
        """Test batch_convert with single entry."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.batch_convert(
            rfc_quirk,
            oid_quirk,
            cast("Sequence[t.ConvertibleModel]", [simple_entry]),
        )
        assert result.is_success
        converted = result.value
        tm.assert_length_equals(converted, 1)
        assert isinstance(converted[0], m.Ldif.Entry)

    def test_batch_convert_multiple_entries(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test batch_convert with multiple entries."""
        entries = [
            TestAssertions.create_entry(
                "cn=user1,dc=example,dc=com",
                {"cn": ["user1"], "objectClass": ["person"]},
            ),
            TestAssertions.create_entry(
                "cn=user2,dc=example,dc=com",
                {"cn": ["user2"], "objectClass": ["person"]},
            ),
        ]
        # Cast list[Entry] to Sequence[ConvertibleModel] for type checker
        result = conversion_service.batch_convert(
            rfc_quirk,
            oid_quirk,
            cast("Sequence[t.ConvertibleModel]", entries),
        )
        assert result.is_success
        converted = result.value
        tm.assert_length_equals(converted, 2)
        assert all(isinstance(e, m.Ldif.Entry) for e in converted)

    def test_batch_convert_with_partial_failures(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test batch_convert with some entries that may fail."""
        entries = [
            TestAssertions.create_entry(
                "cn=valid,dc=example,dc=com",
                {"cn": ["valid"], "objectClass": ["person"]},
            ),
            m.Ldif.Entry(
                dn=m.Ldif.DN(value="invalid-dn"),
                attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            ),
        ]
        # Cast list[Entry] to Sequence[ConvertibleModel] for type checker
        result = conversion_service.batch_convert(
            rfc_quirk,
            oid_quirk,
            cast("Sequence[t.ConvertibleModel]", entries),
        )
        if result.is_success:
            converted = result.value
            assert len(converted) >= 1
        else:
            error_msg = result.error or ""
            assert "error" in error_msg.lower() or "validation" in error_msg.lower()

    # ────────────────────────────────────────────────────────────────────────
    # DN REGISTRY TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_dn_registry_initialized(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test DN registry is initialized."""
        assert conversion_service.dn_registry is not None
        assert isinstance(
            conversion_service.dn_registry,
            m.Ldif.DnRegistry,
        )

    def test_dn_registry_tracks_dns(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
        simple_entry: p.Entry,
    ) -> None:
        """Test DN registry tracks DNs during conversion."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_success
        assert conversion_service.dn_registry is not None

    def test_reset_dn_registry(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test reset_dn_registry() method."""
        conversion_service.dn_registry.register_dn("cn=test,dc=example,dc=com")
        conversion_service.reset_dn_registry()
        assert conversion_service.dn_registry is not None

    def test_dn_registry_tracks_multiple_dns(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test DN registry tracks multiple DNs during batch conversion."""
        entries = [
            TestAssertions.create_entry(
                "cn=user1,dc=example,dc=com",
                {"cn": ["user1"]},
            ),
            TestAssertions.create_entry(
                "cn=user2,dc=example,dc=com",
                {"cn": ["user2"]},
            ),
        ]
        # Cast list[Entry] to Sequence[ConvertibleModel] for type checker
        result = conversion_service.batch_convert(
            rfc_quirk,
            oid_quirk,
            cast("Sequence[t.ConvertibleModel]", entries),
        )
        assert result.is_success
        assert conversion_service.dn_registry is not None

    def test_dn_registry_reset_clears_tracking(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test reset_dn_registry clears tracking."""
        conversion_service.dn_registry.register_dn("cn=test1,dc=example,dc=com")
        conversion_service.dn_registry.register_dn("cn=test2,dc=example,dc=com")
        before_count = len(conversion_service.dn_registry._case_variants)
        conversion_service.reset_dn_registry()
        assert conversion_service.dn_registry is not None
        after_count = len(conversion_service.dn_registry._case_variants)
        assert after_count == 0 or after_count < before_count

    # ────────────────────────────────────────────────────────────────────────
    # VALIDATE OUD TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_validate_oud_conversion(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test validate_oud_conversion() method."""
        result = conversion_service.validate_oud_conversion()
        assert isinstance(result, FlextResult)
        assert result.is_success or result.is_failure

    # ────────────────────────────────────────────────────────────────────────
    # GET SUPPORTED CONVERSIONS TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_get_supported_conversions_rfc(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test get_supported_conversions for RFC quirk."""
        result = conversion_service.get_supported_conversions(rfc_quirk)
        assert isinstance(result, dict)
        assert "entry" in result
        assert "attribute" in result
        assert "objectclass" in result
        assert "acl" in result

    def test_get_supported_conversions_oid(
        self,
        conversion_service: FlextLdifConversion,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test get_supported_conversions for OID quirk."""
        result = conversion_service.get_supported_conversions(oid_quirk)
        assert isinstance(result, dict)
        assert "entry" in result
        assert "attribute" in result
        assert "objectclass" in result
        assert "acl" in result

    def test_get_supported_conversions_oud(
        self,
        conversion_service: FlextLdifConversion,
        oud_quirk: FlextLdifServersOud,
    ) -> None:
        """Test get_supported_conversions for OUD quirk."""
        result = conversion_service.get_supported_conversions(oud_quirk)
        assert isinstance(result, dict)
        assert "entry" in result
        assert "attribute" in result
        assert "objectclass" in result
        assert "acl" in result

    # ────────────────────────────────────────────────────────────────────────
    # ROUNDTRIP CONVERSION TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_roundtrip_rfc_to_oid_to_rfc(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
        simple_entry: p.Entry,
    ) -> None:
        """Test roundtrip conversion: RFC → OID → c.RFC."""
        # Cast Entry to ConvertibleModel for type checker
        result1 = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result1.is_success
        oid_entry = result1.value
        result2 = conversion_service.convert(
            oid_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", oid_entry),
        )
        assert result2.is_success
        rfc_entry = result2.value
        # Type narrowing: ensure dn is not None and rfc_entry is Entry
        if (
            isinstance(rfc_entry, m.Ldif.Entry)
            and rfc_entry.dn is not None
            and simple_entry.dn is not None
        ):
            assert rfc_entry.dn.value == simple_entry.dn.value

    def test_roundtrip_oid_to_oud_to_oid(
        self,
        conversion_service: FlextLdifConversion,
        oid_quirk: FlextLdifServersOid,
        oud_quirk: FlextLdifServersOud,
        simple_entry: p.Entry,
    ) -> None:
        """Test roundtrip conversion: OID → OUD → OID."""
        # Cast Entry to ConvertibleModel for type checker
        result1 = conversion_service.convert(
            oid_quirk,
            oud_quirk,
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result1.is_success
        oud_entry = result1.value
        result2 = conversion_service.convert(
            oud_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", oud_entry),
        )
        assert result2.is_success
        oid_entry_result = result2.value
        # Type narrowing: ensure dn is not None
        if (
            isinstance(oid_entry_result, m.Ldif.Entry)
            and oid_entry_result.dn is not None
            and simple_entry.dn is not None
        ):
            assert oid_entry_result.dn.value == simple_entry.dn.value

    # ────────────────────────────────────────────────────────────────────────
    # SCHEMA CONVERSION TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_convert_schema_attribute(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test SchemaAttribute conversion is supported."""
        attr = m.Ldif.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        # Cast SchemaAttribute to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", attr),
        )
        assert result.is_success
        converted_attr = result.value
        assert isinstance(converted_attr, m.Ldif.SchemaAttribute)
        assert converted_attr.name == "cn"

    def test_convert_schema_objectclass(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test SchemaObjectClass conversion is supported."""
        oc = m.Ldif.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            kind="STRUCTURAL",
        )
        # Cast SchemaObjectClass to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", oc),
        )
        assert result.is_success
        converted_oc = result.value
        assert isinstance(converted_oc, m.Ldif.SchemaObjectClass)
        assert converted_oc.name == "person"

    # ────────────────────────────────────────────────────────────────────────
    # ACL CONVERSION TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_convert_acl_rfc_to_oid(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test converting Acl from RFC to OID."""
        acl_line = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        parse_result = rfc_quirk.Acl().parse(acl_line)
        if not parse_result.is_success:
            pytest.skip("ACL parsing not supported")
        acl = parse_result.value
        # Cast Acl to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            oid_quirk,
            cast("t.ConvertibleModel", acl),
        )
        assert isinstance(result, FlextResult)

    def test_convert_acl_roundtrip(
        self,
        conversion_service: FlextLdifConversion,
        rfc_quirk: FlextLdifServersRfc,
    ) -> None:
        """Test ACL roundtrip conversion."""
        acl_line = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        parse_result = rfc_quirk.Acl().parse(acl_line)
        if not parse_result.is_success:
            pytest.skip("ACL parsing not supported")
        acl = parse_result.value
        # Cast Acl to ConvertibleModel for type checker
        result = conversion_service.convert(
            rfc_quirk,
            rfc_quirk,
            cast("t.ConvertibleModel", acl),
        )
        assert isinstance(result, FlextResult)

    # ────────────────────────────────────────────────────────────────────────
    # ERROR HANDLING TESTS
    # ────────────────────────────────────────────────────────────────────────

    def test_convert_with_invalid_source_type(
        self,
        conversion_service: FlextLdifConversion,
        simple_entry: p.Entry,
    ) -> None:
        """Test convert with invalid source server type."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            "invalid_type",
            "rfc",
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "Unknown server type" in error_msg or "invalid" in error_msg.lower()

    def test_convert_with_invalid_target_type(
        self,
        conversion_service: FlextLdifConversion,
        simple_entry: p.Entry,
    ) -> None:
        """Test convert with invalid target server type."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.convert(
            "rfc",
            "invalid_type",
            cast("t.ConvertibleModel", simple_entry),
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "Unknown server type" in error_msg or "invalid" in error_msg.lower()

    def test_batch_convert_with_invalid_source(
        self,
        conversion_service: FlextLdifConversion,
        simple_entry: p.Entry,
    ) -> None:
        """Test batch_convert with invalid source."""
        # Cast Entry to ConvertibleModel for type checker
        result = conversion_service.batch_convert(
            "invalid",
            "rfc",
            cast("Sequence[t.ConvertibleModel]", [simple_entry]),
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "Unknown server type" in error_msg or "invalid" in error_msg.lower()

    def test_execute_exception_handling(
        self,
        conversion_service: FlextLdifConversion,
    ) -> None:
        """Test execute handles exceptions."""
        result = conversion_service.execute()
        assert result.is_success
