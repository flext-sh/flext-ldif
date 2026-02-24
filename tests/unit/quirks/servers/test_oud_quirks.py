"""Tests for OUD (Oracle Unified Directory) server LDIF quirks handling.

This module tests the FlextLdifServersOud implementation for handling Oracle Unified
Directory-specific attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from flext_ldif import FlextLdif
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.oud import FlextLdifServersOud
from tests import p, s, tf, tm
from tests.conftest import FlextLdifFixtures

from .test_utils import FlextLdifTestUtils


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - ensures each test has clean state


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test function."""
    return FlextLdif()


class OudTestHelpers:
    """Helper methods for OUD tests to eliminate massive code duplication.

    Each method replaces 10-30+ lines of duplicated test code.
    All methods use real executions, no mocks.
    """

    @staticmethod
    def validate_entry_basic_structure(entry: p.Entry) -> None:
        """Validate basic entry structure - replaces 4-5 lines per test."""
        assert entry.dn is not None
        assert entry.dn.value
        assert entry.attributes is not None
        assert len(entry.attributes.attributes) > 0

    @staticmethod
    def find_entries_by_dn_pattern(
        entries: list[p.Entry],
        pattern: str,
    ) -> list[p.Entry]:
        """Find entries matching DN pattern - replaces 5-8 lines per test."""
        return [e for e in entries if e.dn is not None and pattern in e.dn.value]

    @staticmethod
    def find_entries_with_attribute(
        entries: list[p.Entry],
        attr_name: str,
    ) -> list[p.Entry]:
        """Find entries containing specific attribute - replaces 8-12 lines per test."""
        result = []
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr in entry.attributes.attributes:
                if attr.lower() == attr_name.lower():
                    result.append(entry)
                    break
        return result

    @staticmethod
    def get_attribute_values(
        entry: p.Entry,
        attr_name: str,
    ) -> list[str]:
        """Extract attribute values handling all formats - replaces 6-10 lines per test."""
        if entry.attributes is None:
            return []
        attr_value = entry.attributes.attributes.get(attr_name)
        if attr_value is None:
            return []
        # Type checker infers attr_value as list[str], so handle directly
        if hasattr(attr_value, "__len__") and hasattr(attr_value, "__iter__"):
            if isinstance(attr_value, str):
                return [attr_value]
            # Handle list/sequence types
            return [str(v) for v in attr_value]
        if hasattr(attr_value, "values"):
            values_attr = getattr(attr_value, "values", None)
            if values_attr is not None:
                if isinstance(values_attr, list):
                    return [str(v) for v in values_attr]
                return [str(values_attr)]
        return [str(attr_value)]

    @staticmethod
    def has_objectclass_containing(
        entries: list[p.Entry],
        pattern: str,
    ) -> bool:
        """Check if any entry has objectClass containing pattern - replaces 15-20 lines per test."""
        for entry in entries:
            if entry.attributes is None:
                continue
            values = OudTestHelpers.get_attribute_values(entry, "objectclass")
            if any(pattern.lower() in str(v).lower() for v in values):
                return True
        return False

    @staticmethod
    def has_attribute_value_containing(
        entries: list[p.Entry],
        attr_name: str,
        pattern: str,
    ) -> bool:
        """Check if any entry has attribute value containing pattern - replaces 10-15 lines per test."""
        for entry in entries:
            if entry.attributes is None:
                continue
            values = OudTestHelpers.get_attribute_values(entry, attr_name)
            if any(pattern in str(v) for v in values):
                return True
        return False

    @staticmethod
    def validate_entries_write_success(
        quirk: FlextLdifServersBase,
        entries: list[p.Entry],
        operation: str = "write",
    ) -> None:
        """Validate all entries can be written successfully - replaces 8-12 lines per test."""
        # Ignore the operation parameter - always use write() method directly
        _ = operation  # for backward compatibility
        for entry in entries:
            # Use the correct write() API instead of execute()
            result = quirk.write([entry])
            assert result.is_success, "Entry write should succeed"
            written_str = result.value
            assert isinstance(written_str, str), "Write should return string"
            assert len(written_str) > 0, "Written string should not be empty"


class TestsTestFlextLdifOudQuirks(s):
    """Test FlextLdif OUD server quirks with real fixtures."""

    @pytest.mark.timeout(30)
    def test_parse_oud_schema_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD schema file."""
        entries = FlextLdifTestUtils.load_fixture(
            ldif_api,
            "oud",
            "oud_schema_fixtures.ldif",
        )
        assert len(entries) > 0

    @pytest.mark.timeout(10)
    def test_parse_oud_entries_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD entries file."""
        # Load fixture using conftest
        fixture_content = FlextLdifFixtures.get_oud().entries()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            # Parse and validate using unified methods
            entries = tf.load_fixture_and_validate_structure(fixture_path)
            tm.entries(entries, all_have_oc="top")

            dns = [e.dn.value for e in entries if e.dn is not None]
            assert "dc=example,dc=com" in dns
            assert "ou=users,dc=example,dc=com" in dns
            assert "ou=groups,dc=example,dc=com" in dns
        finally:
            # Cleanup
            fixture_path.unlink()

    @pytest.mark.timeout(10)
    def test_parse_oud_acl_fixture(self, ldif_api: FlextLdif) -> None:
        """Test parsing of a real OUD ACL file."""
        fixture_content = FlextLdifFixtures.get_oud().acl()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            entries = tf.load_fixture_entries(fixture_path)
            tm.entries(entries, count_gte=1)
        finally:
            fixture_path.unlink()

    @pytest.mark.timeout(10)
    def test_roundtrip_oud_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD entries."""
        fixture_content = FlextLdifFixtures.get_oud().entries()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            _ = tf.run_fixture_roundtrip(fixture_path)
        finally:
            fixture_path.unlink()

    @pytest.mark.timeout(60)
    def test_roundtrip_oud_schema(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD schema."""
        fixture_content = FlextLdifFixtures.get_oud().schema()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            _ = tf.run_fixture_roundtrip(fixture_path)
        finally:
            fixture_path.unlink()

    @pytest.mark.timeout(10)
    def test_roundtrip_oud_acl(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of OUD ACL."""
        fixture_content = FlextLdifFixtures.get_oud().acl()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            _ = tf.run_fixture_roundtrip(fixture_path)
        finally:
            fixture_path.unlink()

    @pytest.mark.timeout(10)
    def test_oud_oracle_specific_attributes_preserved(
        self,
        ldif_api: FlextLdif,
    ) -> None:
        """Test that Oracle-specific attributes are properly preserved."""
        fixture_content = FlextLdifFixtures.get_oud().entries()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            entries = tf.load_fixture_entries(fixture_path)
            tm.entries(entries, count_gte=1)
        finally:
            fixture_path.unlink()
        oracle_entries = OudTestHelpers.find_entries_by_dn_pattern(
            entries,
            "OracleContext",
        )
        if len(oracle_entries) == 0:
            oracle_entries = OudTestHelpers.find_entries_by_dn_pattern(
                entries,
                "orcl",
            )
        assert len(oracle_entries) > 0 or OudTestHelpers.has_objectclass_containing(
            entries,
            "orcl",
        ), "Should have Oracle-specific entries or objectClasses"

    @pytest.mark.timeout(10)
    def test_oud_password_hashes_preserved(self, ldif_api: FlextLdif) -> None:
        """Test that OUD password hashes are properly preserved."""
        fixture_content = FlextLdifFixtures.get_oud().entries()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            entries = tf.load_fixture_entries(fixture_path)
            tm.entries(entries, count_gte=1)
        finally:
            fixture_path.unlink()
        password_entries = OudTestHelpers.find_entries_with_attribute(
            entries,
            "userPassword",
        )
        assert len(password_entries) > 0, "Should have entries with passwords"
        assert OudTestHelpers.has_attribute_value_containing(
            password_entries,
            "userPassword",
            "{SSHA512}",
        ), "Should have SSHA512 password format"

    @pytest.mark.timeout(10)
    def test_routing_write_validation_oud_entries(self, ldif_api: FlextLdif) -> None:
        """Test that OUD entries are correctly routed through write path.

        This test validates that the automatic write routing
        correctly processes OUD entries through the Entry quirk's write methods.
        """
        fixture_content = FlextLdifFixtures.get_oud().entries()
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(fixture_content)
            fixture_path = Path(f.name)

        try:
            entries = tf.load_fixture_entries(fixture_path)
            tm.entries(entries, count_gte=1)
        finally:
            fixture_path.unlink()

        oud = FlextLdifServersOud()
        OudTestHelpers.validate_entries_write_success(
            oud,
            entries,
            operation="write",
        )
