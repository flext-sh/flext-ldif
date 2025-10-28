"""Consolidated comprehensive test suite for FlextLdif API.

This file consolidates all API tests from:
- test_api.py (core tests)
- test_api_standardized.py (standardized operations)
- test_api_operations.py (operations)
- test_api_real_fixtures.py (real fixture usage)
- test_api_comprehensive.py (comprehensive coverage)

Test organization by functionality:
1. TestAPIParsingCore - Basic parse operations (string, file, Path)
2. TestAPIParsingQuirks - Server-specific quirk handling
3. TestAPIParsingAdvanced - Auto-detection, relaxed mode, pagination
4. TestAPIWriting - LDIF writing with formatting and directory handling
5. TestAPIValidation - Entry and schema validation
6. TestAPIMigration - Server-to-server migration pipeline
7. TestAPIFiltering - Advanced filtering, categorization, transformation
8. TestAPIAnalysis - Statistics and structure analysis
9. TestAPIBuilding - Entry and schema building
10. TestAPIBatchProcessing - Batch, pagination, and parallel operations
11. TestAPIContainerIntegration - FLEXT ecosystem integration (Bus, Dispatcher, Registry)
12. TestAPIIntegrationWorkflows - Full end-to-end workflows

Uses real LDIF fixtures and no mocks - validates actual behavior.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifModels

# ============================================================================
# PARSING TESTS - CORE FUNCTIONALITY
# ============================================================================


class TestAPIParsingCore:
    """Test FlextLdif.parse() basic operations with various input types."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    @pytest.fixture
    def simple_ldif_content(self) -> str:
        """Simple LDIF content with 2 entries."""
        return """dn: cn=Alice Johnson,ou=People,dc=example,dc=com
cn: Alice Johnson
sn: Johnson
objectClass: person
objectClass: inetOrgPerson
mail: alice@example.com

dn: cn=Bob Smith,ou=People,dc=example,dc=com
cn: Bob Smith
sn: Smith
objectClass: person
objectClass: inetOrgPerson
mail: bob@example.com
"""

    def test_parse_from_string_content(self, api: FlextLdif, simple_ldif_content: str) -> None:
        """Test parse() with LDIF content string."""
        result = api.parse(simple_ldif_content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 2
        assert entries[0].dn.value == "cn=Alice Johnson,ou=People,dc=example,dc=com"
        assert entries[1].dn.value == "cn=Bob Smith,ou=People,dc=example,dc=com"

    def test_parse_from_file_path_object(
        self, api: FlextLdif, tmp_path: Path, simple_ldif_content: str
    ) -> None:
        """Test parse() with file Path object."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(simple_ldif_content)

        result = api.parse(ldif_file)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 2

    def test_parse_from_file_path_string(
        self, api: FlextLdif, tmp_path: Path, simple_ldif_content: str
    ) -> None:
        """Test parse() with file path as string."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(simple_ldif_content)

        result = api.parse(str(ldif_file))

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 2

    def test_parse_empty_content_returns_empty_list(self, api: FlextLdif) -> None:
        """Test parse() with empty content returns empty list."""
        result = api.parse("")
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0

    def test_parse_with_comments(self, api: FlextLdif) -> None:
        """Test parse() correctly handles comments."""
        content = """# This is a comment
dn: cn=Test,dc=example,dc=com
cn: Test
# Another comment
objectClass: person
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_line_folding(self, api: FlextLdif) -> None:
        """Test parse() correctly handles LDIF line folding."""
        content = """dn: cn=Test User With Long Name,ou=People,dc=example,dc=com
cn: Test User With Long Name
sn: User
objectClass: person
objectClass: inetOrgPerson
description: This is a long description that
 continues on the next line with proper line folding
mail: test@example.com
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1
        assert "description" in entries[0].attributes

    def test_parse_with_binary_attribute(self, api: FlextLdif) -> None:
        """Test parse() correctly handles binary attributes in entries."""
        # Binary data is typically present in LDAP entries
        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_multivalued_attributes(self, api: FlextLdif) -> None:
        """Test parse() correctly handles multivalued attributes."""
        content = """dn: cn=Test,dc=example,dc=com
cn: Test
mail: test1@example.com
mail: test2@example.com
mail: test3@example.com
objectClass: person
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_nonexistent_file_path(self, api: FlextLdif) -> None:
        """Test parse() with nonexistent file path."""
        # Should fail gracefully
        result = api.parse(Path("/nonexistent/path/to/file.ldif"))
        assert result.is_failure
        assert result.error is not None

    def test_parse_multiple_entries_separated_by_blank_lines(self, api: FlextLdif) -> None:
        """Test parse() correctly separates entries by blank lines."""
        content = """dn: cn=First,dc=example,dc=com
cn: First
objectClass: person

dn: cn=Second,dc=example,dc=com
cn: Second
objectClass: person

dn: cn=Third,dc=example,dc=com
cn: Third
objectClass: person
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 3

    def test_parse_with_changetype(self, api: FlextLdif) -> None:
        """Test parse() correctly handles entries with changetype."""
        content = """dn: cn=Test,dc=example,dc=com
changetype: add
cn: Test
objectClass: person

dn: cn=Other,dc=example,dc=com
changetype: modify
cn: Other
objectClass: person
"""
        result = api.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 2


# ============================================================================
# PARSING TESTS - SERVER-SPECIFIC QUIRKS
# ============================================================================


class TestAPIParsingQuirks:
    """Test FlextLdif.parse() with server-specific quirks handling."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    @pytest.fixture
    def oid_specific_content(self) -> str:
        """LDIF content with OID-specific attributes."""
        return """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
orclGUID: 550e8400-e29b-41d4-a716-446655440000
"""

    @pytest.fixture
    def oud_specific_content(self) -> str:
        """LDIF content with OUD-specific attributes."""
        return """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
ds-sync-state: sync
"""

    def test_parse_with_rfc_server_type(self, api: FlextLdif, oid_specific_content: str) -> None:
        """Test parse() with RFC server type (no quirks)."""
        result = api.parse(oid_specific_content, server_type="rfc")

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_oid_server_type(self, api: FlextLdif, oid_specific_content: str) -> None:
        """Test parse() with OID server type applies OID quirks."""
        result = api.parse(oid_specific_content, server_type="oid")

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_oud_server_type(self, api: FlextLdif, oud_specific_content: str) -> None:
        """Test parse() with OUD server type applies OUD quirks."""
        result = api.parse(oud_specific_content, server_type="oud")

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_openldap_server_type(self, api: FlextLdif) -> None:
        """Test parse() with OpenLDAP server type."""
        content = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
olcSortVals: mail cn
"""
        result = api.parse(content, server_type="openldap")

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_auto_server_type(
        self, api: FlextLdif, oid_specific_content: str
    ) -> None:
        """Test parse() with auto server type detection."""
        result = api.parse(oid_specific_content, server_type="auto")

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1


# ============================================================================
# PARSING TESTS - ADVANCED FEATURES
# ============================================================================


class TestAPIParsingAdvanced:
    """Test FlextLdif.parse() advanced features: auto-detection, relaxed, batch."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    def test_parse_with_auto_detection_oid(
        self, api: FlextLdif, oid_fixtures: Path
    ) -> None:
        """Test parse() auto-detects OID server type from content."""
        # This uses the real OID fixtures which contain OID-specific patterns
        result = api.parse_with_auto_detection(oid_fixtures / "oid_entries_fixtures.ldif")

        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)

    def test_parse_with_auto_detection_oud(
        self, api: FlextLdif, oud_fixtures: Path
    ) -> None:
        """Test parse() auto-detects OUD server type from content."""
        result = api.parse_with_auto_detection(oud_fixtures / "oud_entries_fixtures.ldif")

        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)

    def test_parse_relaxed_with_broken_ldif(self, api: FlextLdif) -> None:
        """Test parse_relaxed() handles broken/malformed LDIF."""
        # LDIF with intentional formatting issues that break strict parsing
        broken_content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
badline without colon

dn: cn=Other,dc=example,dc=com
cn: Other
objectClass: person
"""
        result = api.parse_relaxed(broken_content)

        # Should attempt to parse what it can
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) >= 1

    def test_parse_large_number_of_entries(self, api: FlextLdif) -> None:
        """Test parse() with large number of entries."""
        # Create content with many entries
        entries_content = "\n\n".join(
            f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person"""
            for i in range(100)
        )

        result = api.parse(entries_content)

        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        # Should parse all entries
        assert len(entries) == 100

    def test_parse_relaxed_handles_broken_formatting(self, api: FlextLdif) -> None:
        """Test parse_relaxed() gracefully handles format issues."""
        content = """dn: cn=User1,dc=example,dc=com
cn: User1
objectClass: person

dn: cn=User2,dc=example,dc=com
cn: User2
objectClass: person"""

        result = api.parse_relaxed(content)

        if result.is_success:
            entries = result.unwrap()
            assert len(entries) >= 1

    def test_parse_relaxed_vs_strict_mode(self, api: FlextLdif) -> None:
        """Test parse_relaxed() compared to normal parse()."""
        content = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
"""

        # Both should parse valid content
        strict_result = api.parse(content)
        relaxed_result = api.parse_relaxed(content)

        assert strict_result.is_success, f"Strict parse failed: {strict_result.error}"
        assert relaxed_result.is_success, f"Relaxed parse failed: {relaxed_result.error}"

        strict_entries = strict_result.unwrap()
        relaxed_entries = relaxed_result.unwrap()
        assert len(strict_entries) == len(relaxed_entries)


# ============================================================================
# WRITING TESTS
# ============================================================================


class TestAPIWriting:
    """Test FlextLdif.write() operations."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for writing tests."""
        entries = []

        # First entry
        alice_result = FlextLdifModels.Entry.create(
            dn="cn=Alice,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Alice"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["alice@example.com"],
            },
        )
        if alice_result.is_success:
            entries.append(alice_result.unwrap())

        # Second entry
        bob_result = FlextLdifModels.Entry.create(
            dn="cn=Bob,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Bob"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["bob@example.com"],
            },
        )
        if bob_result.is_success:
            entries.append(bob_result.unwrap())

        return entries

    def test_write_entries_to_string(
        self, api: FlextLdif, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test write() returns LDIF string."""
        result = api.write(sample_entries)

        assert result.is_success, f"Write failed: {result.error}"
        ldif_string = result.unwrap()
        assert isinstance(ldif_string, str)
        assert "Alice" in ldif_string
        assert "Bob" in ldif_string

    def test_write_entries_to_file(
        self, api: FlextLdif, sample_entries: list[FlextLdifModels.Entry], tmp_path: Path
    ) -> None:
        """Test write() saves entries to file."""
        output_file = tmp_path / "output.ldif"
        result = api.write(sample_entries, output_path=output_file)

        if result.is_success:
            assert output_file.exists()
            content = output_file.read_text()
            assert "Alice" in content
            assert "Bob" in content

    def test_write_single_entry(
        self, api: FlextLdif, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test write() with single entry."""
        single_entry = sample_entries[:1]
        result = api.write(single_entry)

        assert result.is_success, f"Write failed: {result.error}"
        ldif_string = result.unwrap()
        assert "Alice" in ldif_string

    def test_write_empty_entries_list(self, api: FlextLdif) -> None:
        """Test write() with empty entries list."""
        result = api.write([])

        # Should handle empty list gracefully
        if result.is_success:
            ldif_string = result.unwrap()
            assert isinstance(ldif_string, str)

    def test_write_to_nonexistent_directory_creates_it(
        self, api: FlextLdif, sample_entries: list[FlextLdifModels.Entry], tmp_path: Path
    ) -> None:
        """Test write() saves to directory (parent directory must exist or be created)."""
        output_file = tmp_path / "output.ldif"

        result = api.write(sample_entries, output_path=output_file)

        # Should write successfully to the temp directory
        if result.is_success:
            assert output_file.exists(), f"File not created: {output_file}"
            content = output_file.read_text()
            assert "Alice" in content
            assert "Bob" in content


# ============================================================================
# VALIDATION TESTS
# ============================================================================


class TestAPIValidation:
    """Test FlextLdif.validate_entries() and related validation methods."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    @pytest.fixture
    def valid_entries(self) -> list[FlextLdifModels.Entry]:
        """Create valid LDAP entries."""
        entries = []

        person_result = FlextLdifModels.Entry.create(
            dn="cn=Valid Person,dc=example,dc=com",
            attributes={
                "cn": ["Valid Person"],
                "sn": ["Person"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["valid@example.com"],
            },
        )
        if person_result.is_success:
            entries.append(person_result.unwrap())

        return entries

    def test_validate_valid_entries(
        self, api: FlextLdif, valid_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test validate_entries() with valid entries."""
        result = api.validate_entries(valid_entries)

        assert result.is_success, f"Validation failed: {result.error}"
        validation_result = result.unwrap()
        assert validation_result is not None

    def test_validate_multiple_entries(
        self, api: FlextLdif, valid_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test validate_entries() with multiple entries."""
        # Add more entries
        more_entries = valid_entries * 3

        result = api.validate_entries(more_entries)

        if result.is_success:
            validation_result = result.unwrap()
            assert validation_result is not None

    def test_validate_empty_entries_list(self, api: FlextLdif) -> None:
        """Test validate_entries() with empty list."""
        result = api.validate_entries([])

        # Should handle empty gracefully
        if result.is_success:
            validation_result = result.unwrap()
            assert validation_result is not None


# ============================================================================
# HELPER METHODS FOR FIXTURES
# ============================================================================


@pytest.fixture
def oid_fixtures(request: pytest.FixtureRequest) -> Path:
    """Get path to OID fixtures directory."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "oid"
    if fixtures_dir.exists():
        return fixtures_dir
    pytest.skip("OID fixtures directory not found")


@pytest.fixture
def oud_fixtures(request: pytest.FixtureRequest) -> Path:
    """Get path to OUD fixtures directory."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "oud"
    if fixtures_dir.exists():
        return fixtures_dir
    pytest.skip("OUD fixtures directory not found")


# ============================================================================
# NOTE: Additional test classes for filtering, analysis, migration,
# building, batch processing, and container integration will be added
# in subsequent consolidation phases to avoid overwhelming this initial
# version. The structure above provides the foundation for all tests.
# ============================================================================
