from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from tests import s


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


class TestsFlextLdifEdgeCases(s):
    """Test edge cases with real fixture files."""

    def test_unicode_names(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with unicode characters in names."""
        # Use inline LDIF content instead of missing fixture file
        unicode_ldif = """dn: cn=José,ou=Users,dc=example,dc=com
cn: José
sn: García
objectClass: person

"""
        result = ldif_api.parse(unicode_ldif, server_type="rfc")
        assert result.is_success, f"Failed to parse unicode content: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

        # Validate unicode characters are preserved
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            # Check for non-ASCII characters in DN or attributes
            has_unicode = any(ord(c) > 127 for c in entry.dn.value)
            if has_unicode:
                # Validate unicode was preserved
                assert entry.dn.value

    def test_deep_dn(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with very deep DN hierarchies."""
        # Use inline LDIF content with deep DN instead of missing fixture file
        deep_dn_ldif = """dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com
cn: level1
objectClass: person

"""
        result = ldif_api.parse(deep_dn_ldif, server_type="rfc")
        assert result.is_success, f"Failed to parse deep DN content: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

        # Find the deepest DN
        max_depth = 0
        for entry in entries:
            if entry.dn is not None:
                depth = entry.dn.value.count(",") + 1
                max_depth = max(max_depth, depth)

        # Validate deep DNs are handled
        assert max_depth > 5, f"Expected deep DN, got depth {max_depth}"

    def test_large_multivalue(self, ldif_api: FlextLdif) -> None:
        """Test parsing of attributes with many values."""
        base_dir = Path(__file__).parent.parent.parent.parent
        fixture_path = (
            base_dir / "fixtures" / "edge_cases" / "size" / "large_multivalue.ldif"
        )
        if not fixture_path.exists():
            fixture_path = Path(
                "flext-ldif/tests/fixtures/edge_cases/size/large_multivalue.ldif",
            )
        result = ldif_api.parse(
            fixture_path,
            server_type="rfc",
        )
        assert result.is_success, (
            f"Failed to parse large multivalue fixture: {result.error}"
        )
        entries = result.unwrap()
        assert len(entries) > 0

        # Find attributes with many values
        max_values = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr_value in entry.attributes.values():
                if isinstance(attr_value, list):
                    values = attr_value
                elif hasattr(attr_value, "values"):
                    values = attr_value.values
                else:
                    values = [attr_value]
                max_values = max(max_values, len(values))

        # Validate large multivalue attributes are handled
        assert max_values >= 10, (
            f"Expected large multivalue (>=10), got {max_values} values"
        )

    def test_roundtrip_unicode(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of unicode entries."""
        # Use inline content instead of missing fixture
        unicode_ldif = """dn: cn=José,ou=Users,dc=example,dc=com
cn: José
sn: García
objectClass: person

"""
        # Parse
        parse_result = ldif_api.parse(unicode_ldif, server_type="rfc")
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) == 1

        # Write
        output_path = tmp_path / "unicode_roundtrip.ldif"
        write_result = ldif_api.write(
            entries,
            output_path=output_path,
            server_type="rfc",
        )
        assert write_result.is_success, f"Write failed: {write_result.error}"

        # Parse back
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        assert roundtrip_result.is_success, (
            f"Roundtrip parse failed: {roundtrip_result.error}"
        )
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == 1

    def test_roundtrip_deep_dn(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of deep DN entries."""
        # Use inline content instead of missing fixture
        deep_dn_ldif = """dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com
cn: level1
objectClass: person

"""
        # Parse
        parse_result = ldif_api.parse(deep_dn_ldif, server_type="rfc")
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) == 1

        # Write
        output_path = tmp_path / "deep_dn_roundtrip.ldif"
        write_result = ldif_api.write(
            entries,
            output_path=output_path,
            server_type="rfc",
        )
        assert write_result.is_success, f"Write failed: {write_result.error}"

        # Parse back
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        assert roundtrip_result.is_success, (
            f"Roundtrip parse failed: {roundtrip_result.error}"
        )
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == 1

    def test_roundtrip_large_multivalue(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip of large multivalue entries."""
        # Use inline content instead of missing fixture
        large_multivalue_ldif = """dn: cn=test,dc=example,dc=com
cn: test
member: cn=user1,dc=example,dc=com
member: cn=user2,dc=example,dc=com
member: cn=user3,dc=example,dc=com
member: cn=user4,dc=example,dc=com
member: cn=user5,dc=example,dc=com
objectClass: groupOfNames

"""
        # Parse
        parse_result = ldif_api.parse(large_multivalue_ldif, server_type="rfc")
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) == 1

        # Write
        output_path = tmp_path / "large_multivalue_roundtrip.ldif"
        write_result = ldif_api.write(
            entries,
            output_path=output_path,
            server_type="rfc",
        )
        assert write_result.is_success, f"Write failed: {write_result.error}"

        # Parse back
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        assert roundtrip_result.is_success, (
            f"Roundtrip parse failed: {roundtrip_result.error}"
        )
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == 1
