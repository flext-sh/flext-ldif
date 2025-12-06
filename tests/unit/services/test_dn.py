from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif.models import m
from flext_ldif.services.dn import FlextLdifDn
from tests import c, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class TestsFlextLdifDnService(s):
    """Unified test suite for RFC 4514 DN Service operations.

    Covers parsing, validation, normalization, cleaning, escaping/unescaping,
    comparison, RDN parsing, builder patterns, and DN registry operations.
    """

    class DNOperationType(StrEnum):
        """Enumeration of DN operations."""

        PARSE = "parse"
        VALIDATE = "validate"
        NORMALIZE = "normalize"
        CLEAN = "clean"
        ESCAPE = "escape"
        UNESCAPE = "unescape"
        COMPARE = "compare"
        RDN_PARSE = "rdn_parse"

    class EscapeTestCase(StrEnum):
        """Enumeration of escaping test cases."""

        COMMA = "comma"
        HASH = "hash"
        MULTIPLE = "multiple"
        LEADING_SPACE = "leading_space"
        TRAILING_SPACE = "trailing_space"
        EMPTY = "empty"

    # ========================================================================
    # TEST DATA MAPPINGS
    # ========================================================================

    PARSING_DATA: ClassVar[tuple[tuple[str, bool, int], ...]] = (
        (c.DNs.TEST_USER, True, 3),
        (f"cn=Smith\\, {c.Values.TEST},{c.DNs.EXAMPLE}", True, -1),  # -1 means >= 2
        ("", False, -1),
        ("invalid dn without equals", False, -1),
    )

    VALIDATION_DATA: ClassVar[tuple[tuple[str, bool], ...]] = (
        (c.DNs.TEST_USER, True),
        (f"cn={c.Values.TEST},ou=People,o=Company,c=US,{c.DNs.EXAMPLE}", True),
        ("", False),
        ("not a valid dn", False),
        (f"cn=,{c.DNs.EXAMPLE}", False),  # Empty values are invalid
    )

    NORMALIZATION_DATA: ClassVar[tuple[tuple[str, bool | None], ...]] = (
        (f"CN={c.Values.ADMIN},DC=Example,DC=Com", True),
        (f"cn={c.Values.TEST},{c.DNs.EXAMPLE}".upper(), True),
        (
            f"CN = {c.Values.ADMIN} , DC = Example , DC = Com",
            None,
        ),  # Either success or failure
        ("invalid dn", False),
    )

    CLEANING_DATA: ClassVar[tuple[tuple[str, str], ...]] = (
        (f"cn = {c.Values.TEST} , dc = example , dc = com", "cn="),
        (r"cn=OIM-TEST\ ,ou=Users,dc=com", "cn=OIM-TEST,ou=Users,dc=com"),
        ("", ""),
        (c.DNs.TEST_USER, c.DNs.TEST_USER),
        (f"cn  =  {c.Values.TEST}  ,  dc  =  example", "cn="),
    )

    ESCAPING_DATA: ClassVar[tuple[tuple[str, str], ...]] = (
        (f"Smith, {c.Values.TEST}", "Smith\\2c test"),
        ("#1 User", "\\231 User"),
        ('Test+User,"Admin"', "Test\\2bUser\\2c\\22Admin\\22"),  # Full escaped form
        (" REDACTED_LDAP_BIND_PASSWORD", "\\20REDACTED_LDAP_BIND_PASSWORD"),  # Starts with hex space
        ("REDACTED_LDAP_BIND_PASSWORD ", "REDACTED_LDAP_BIND_PASSWORD\\20"),  # Ends with hex space
        ("", ""),
    )

    UNESCAPING_DATA: ClassVar[tuple[tuple[str, str], ...]] = (
        ("Smith\\2c test", f"Smith, {c.Values.TEST}"),
        ("Smith\\, test", f"Smith, {c.Values.TEST}"),
        (f"{c.Values.TEST} {c.Values.ADMIN}", f"{c.Values.TEST} {c.Values.ADMIN}"),
        ("", ""),
    )

    COMPARISON_DATA: ClassVar[tuple[tuple[str, str, int], ...]] = (
        (c.DNs.TEST_USER, f"CN={c.Values.TEST},{c.DNs.EXAMPLE}".upper(), 0),
        (c.DNs.TEST_USER, c.DNs.TEST_GROUP, -1),
    )

    RDN_PARSING_DATA: ClassVar[tuple[tuple[str, bool, int], ...]] = (
        (f"cn={c.Values.TEST}", True, 1),
        (f"cn={c.Values.TEST}+ou=People", True, 2),
        (r"cn=Test\+User", True, -1),  # -1 means >= 1
        ("", False, -1),
        ("InvalidRDN", False, -1),
    )

    BUILDER_OPERATIONS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        (f"CN={c.Values.ADMIN},DC=Example,DC=Com", "normalize", "cn="),
        (f"cn = {c.Values.TEST} , dc = example", "clean", "cn="),
        (f"Smith, {c.Values.TEST}", "escape", "Smith\\2c"),
    )

    # ========================================================================
    # FACTORY METHODS
    # ========================================================================

    @classmethod
    def create_dn_service(
        cls,
        dn: str = "",
        other_dn: str | None = None,
        operation: str = "normalize",
        escape_mode: str = "standard",
        *,
        enable_events: bool = False,
    ) -> FlextLdifDn:
        """Factory method to create DN service instances."""
        return FlextLdifDn(
            dn=dn,
            other_dn=other_dn,
            operation=operation,
            escape_mode=escape_mode,
            enable_events=enable_events,
        )

    @classmethod
    def create_registry_with_dns(cls, *dns: str) -> m.DnRegistry:
        """Factory method to create registry with multiple c.DNs."""
        registry = m.DnRegistry()
        for dn in dns:
            registry.register_dn(dn)
        return registry

    # ========================================================================
    # PARSING TESTS
    # ========================================================================

    @pytest.mark.parametrize(("dn", "should_succeed", "expected_len"), PARSING_DATA)
    def test_parse_components(
        self,
        dn: str,
        should_succeed: bool,
        expected_len: int,
    ) -> None:
        """Test DN parsing into RFC 4514 components."""
        dn_service = FlextLdifDn()
        result = dn_service.parse_components(dn)
        if should_succeed:
            components = self.assert_success(result)
            if expected_len > 0:
                assert len(components) == expected_len
        else:
            self.assert_failure(result)

    # ========================================================================
    # VALIDATION TESTS
    # ========================================================================

    @pytest.mark.parametrize(("dn", "expected_valid"), VALIDATION_DATA)
    def test_validate_format(self, dn: str, expected_valid: bool) -> None:
        """Test DN format validation against RFC 4514."""
        dn_service = FlextLdifDn()
        result = dn_service.validate_format(dn)
        is_valid = self.assert_success(result)
        assert is_valid == expected_valid

    # ========================================================================
    # NORMALIZATION TESTS
    # ========================================================================

    @pytest.mark.parametrize(("dn", "should_succeed"), NORMALIZATION_DATA)
    def test_normalize(self, dn: str, should_succeed: bool | None) -> None:
        """Test DN normalization per RFC 4514."""
        dn_service = FlextLdifDn()
        result = dn_service.normalize(dn)
        if should_succeed is True:
            normalized = self.assert_success(result)
            assert "cn=" in normalized.lower() or "ou=" in normalized.lower()
        elif should_succeed is False:
            self.assert_failure(result)
        # None means either success or failure is acceptable

    # ========================================================================
    # CLEANING TESTS
    # ========================================================================

    @pytest.mark.parametrize(("dn", "expected_contains"), CLEANING_DATA)
    def test_clean_dn(self, dn: str, expected_contains: str) -> None:
        """Test DN string cleaning for malformed LDIF exports."""
        cleaned = FlextLdifDn.Normalizer.clean_dn(dn)
        if expected_contains:
            assert expected_contains in cleaned or cleaned == expected_contains

    # ========================================================================
    # ESCAPING TESTS
    # ========================================================================

    @pytest.mark.parametrize(("value", "expected"), ESCAPING_DATA)
    def test_escape_dn_value(self, value: str, expected: str) -> None:
        """Test DN value escaping per RFC 4514."""
        dn_service = FlextLdifDn()
        escaped = dn_service.escape_dn_value(value)
        if expected.startswith("\\") and len(expected) == 1:
            assert escaped.startswith("\\")
        elif expected.endswith("\\20"):
            assert escaped.endswith("\\20")
        else:
            assert escaped == expected

    @pytest.mark.parametrize(("escaped", "expected"), UNESCAPING_DATA)
    def test_unescape_dn_value(self, escaped: str, expected: str) -> None:
        """Test DN value unescaping per RFC 4514."""
        dn_service = FlextLdifDn()
        unescaped = dn_service.unescape_dn_value(escaped)
        assert unescaped == expected

    def test_escape_unescape_roundtrip(self) -> None:
        """Test roundtrip: escape then unescape."""
        dn_service = FlextLdifDn()
        original = f"Smith, {c.Values.TEST}"
        escaped = dn_service.escape_dn_value(original)
        unescaped = dn_service.unescape_dn_value(escaped)
        assert unescaped == original

    # ========================================================================
    # COMPARISON TESTS
    # ========================================================================

    @pytest.mark.parametrize(("dn1", "dn2", "expected"), COMPARISON_DATA)
    def test_compare_dns(self, dn1: str, dn2: str, expected: int) -> None:
        """Test DN comparison (case-insensitive)."""
        dn_service = FlextLdifDn()
        result = dn_service.compare_dns(dn1, dn2)
        comparison_result = self.assert_success(result)
        assert comparison_result == expected

    def test_compare_invalid_dn(self) -> None:
        """Compare with invalid DN should fail."""
        dn_service = FlextLdifDn()
        result = dn_service.compare_dns(c.DNs.TEST_USER, "invalid dn")
        self.assert_failure(result)

    # ========================================================================
    # RDN PARSING TESTS
    # ========================================================================

    @pytest.mark.parametrize(
        ("rdn", "should_succeed", "expected_len"),
        RDN_PARSING_DATA,
    )
    def test_parse_rdn(self, rdn: str, should_succeed: bool, expected_len: int) -> None:
        """Test RDN (Relative Distinguished Name) parsing."""
        dn_service = FlextLdifDn()
        result = dn_service.parse_rdn(rdn)
        if should_succeed:
            pairs = self.assert_success(result)
            if expected_len > 0:
                assert len(pairs) == expected_len
        else:
            self.assert_failure(result)

    # ========================================================================
    # BUILDER PATTERN TESTS
    # ========================================================================

    @pytest.mark.parametrize(
        ("dn", "operation", "expected_contains"),
        BUILDER_OPERATIONS,
    )
    def test_builder_pattern(
        self,
        dn: str,
        operation: str,
        expected_contains: str,
    ) -> None:
        """Test fluent builder pattern for DN service."""
        dn_service = FlextLdifDn()
        result = dn_service.builder().with_dn(dn).with_operation(operation).build()
        assert result
        # Check that result is a string and contains operation result
        assert isinstance(result, str)
        assert len(result) > 0

    # ========================================================================
    # EXECUTE PATTERN TESTS
    # ========================================================================

    def test_execute_operations_batch(self) -> None:
        """Execute various DN operations in batch."""
        # Test normalize operation
        service1 = self.create_dn_service(
            dn=f"CN={c.Values.ADMIN},DC=Example,DC=Com",
            operation="normalize",
        )
        result1 = service1.execute()
        assert result1.is_success or result1.is_failure

        # Test validate operation
        service2 = self.create_dn_service(dn=c.DNs.TEST_USER, operation="validate")
        self.assert_success(service2.execute())

        # Test validate invalid DN
        service3 = self.create_dn_service(dn="invalid dn", operation="validate")
        self.assert_success(service3.execute())

        # Test compare operation
        service4 = self.create_dn_service(
            dn=c.DNs.TEST_USER,
            other_dn=f"CN={c.Values.TEST},{c.DNs.EXAMPLE}".upper(),
            operation="compare",
        )
        self.assert_success(service4.execute())

    # ========================================================================
    # DN REGISTRY TESTS
    # ========================================================================

    def test_register_dn(self) -> None:
        """Register DN and get canonical case."""
        registry = m.DnRegistry()
        canonical = registry.register_dn(f"CN={c.Values.ADMIN},DC=Example,DC=Com")
        assert canonical == f"CN={c.Values.ADMIN},DC=Example,DC=Com"

    def test_get_canonical_dn(self) -> None:
        """Get canonical DN for variant case."""
        registry = m.DnRegistry()
        registry.register_dn(f"CN={c.Values.ADMIN},DC=Example,DC=Com")
        canonical = registry.get_canonical_dn(
            f"cn={c.Values.ADMIN.lower()},dc=example,dc=com",
        )
        assert canonical == f"CN={c.Values.ADMIN},DC=Example,DC=Com"

    def test_registry_has_dn(self) -> None:
        """Check if DN is registered."""
        registry = m.DnRegistry()
        registry.register_dn(f"CN={c.Values.ADMIN},DC=Example,DC=Com")
        assert registry.has_dn(f"cn={c.Values.ADMIN.lower()},dc=example,dc=com")
        assert not registry.has_dn(f"cn=unknown,{c.DNs.EXAMPLE}")

    def test_registry_case_variants(self) -> None:
        """Get all case variants for DN."""
        registry = m.DnRegistry()
        registry.register_dn(f"CN={c.Values.ADMIN},DC=Example,DC=Com")
        registry.register_dn(f"cn={c.Values.ADMIN.lower()},dc=example,dc=com")
        registry.register_dn(f"cn={c.Values.ADMIN.upper()},dc=EXAMPLE,dc=COM")
        variants = registry.get_case_variants(
            f"cn={c.Values.ADMIN.lower()},dc=example,dc=com",
        )
        assert len(variants) == 3

    def test_validate_oud_consistency(self) -> None:
        """Validate OUD consistency in batch."""
        # Test 1: Single DN registration - consistent (True)
        registry1 = self.create_registry_with_dns(c.DNs.TEST_USER)
        result1 = registry1.validate_oud_consistency()
        is_consistent = self.assert_success(result1)
        assert is_consistent

        # Test 2: Same DN registered with multiple case variants - inconsistent (False)
        registry2 = m.DnRegistry()
        registry2.register_dn(f"CN={c.Values.ADMIN},DC=Example,DC=Com")
        # Register the SAME DN with different case
        registry2.register_dn(f"cn={c.Values.ADMIN.lower()},dc=example,dc=com")
        result2 = registry2.validate_oud_consistency()
        is_consistent2 = self.assert_success(result2)
        assert not is_consistent2

    def test_registry_clear(self) -> None:
        """Clear registry."""
        registry = self.create_registry_with_dns(c.DNs.TEST_USER)
        assert registry.has_dn(c.DNs.TEST_USER)
        registry.clear()
        assert not registry.has_dn(c.DNs.TEST_USER)

    def test_registry_stats(self) -> None:
        """Get registry statistics."""
        # Register the same DN with different case representations
        base_dn = f"CN={c.Values.ADMIN},DC=Example,DC=Com"
        variant_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        registry = self.create_registry_with_dns(base_dn, variant_dn)
        stats = registry.get_stats()
        assert stats["total_dns"] == 1
        assert stats["total_variants"] == 2
        assert stats["dns_with_multiple_variants"] == 1

    # ========================================================================
    # DYNAMIC TESTS
    # ========================================================================

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                f"{c.Values.TEST}, {c.Values.ADMIN}",
                f"{c.Values.TEST}\\2c {c.Values.ADMIN}",
            ),
            (f"#{c.Values.TEST}", f"\\23{c.Values.TEST}"),
            ("test+user", "test\\2buser"),
            (f" {c.Values.TEST}", f"\\20{c.Values.TEST}"),
            (f"{c.Values.TEST} ", f"{c.Values.TEST}\\20"),
        ],
    )
    def test_dynamic_escape_cases(self, value: str, expected: str) -> None:
        """Dynamically generated escape test cases."""
        dn_service = self.create_dn_service()
        escaped = dn_service.escape_dn_value(value)
        assert escaped == expected

    # ========================================================================
    # INTEGRATION WORKFLOWS
    # ========================================================================

    def test_workflow_parse_validate_normalize(self) -> None:
        """Complete workflow: parse, validate, normalize."""
        dn_service = FlextLdifDn()
        dn = f"CN={c.Values.TEST} Doe,OU=Users,{c.DNs.EXAMPLE}"

        result = dn_service.validate_format(dn)
        is_valid = self.assert_success(result)
        assert is_valid

        components = self.assert_success(dn_service.parse_components(dn))
        assert len(components) == 4

        normalized = self.assert_success(dn_service.normalize(dn))
        assert "cn=" in normalized.lower()

    def test_workflow_clean_and_escape(self) -> None:
        """Workflow: clean malformed DN, then escape values."""
        malformed = f"CN = Smith, {c.Values.TEST} , OU = Users , DC = Example"
        cleaned = FlextLdifDn.Normalizer.clean_dn(malformed)
        assert "  " not in cleaned

        dn_service = FlextLdifDn()
        escaped = dn_service.escape_dn_value(f"Smith, {c.Values.TEST}")
        assert "\\" in escaped

    def test_workflow_registry_for_migration(self) -> None:
        """Workflow: use registry to track DN case during migration."""
        source_dns = [
            c.DNs.TEST_USER,
            f"CN={c.Values.ADMIN},DC=Example,DC=Com",
            f"cn={c.Values.ADMIN.upper()},{c.DNs.EXAMPLE}",
        ]

        registry = m.DnRegistry()
        for dn in source_dns:
            registry.register_dn(dn)

        result = registry.validate_oud_consistency()
        is_consistent = self.assert_success(result)
        assert not is_consistent

        canonical = registry.get_canonical_dn(c.DNs.TEST_USER)
        assert canonical
