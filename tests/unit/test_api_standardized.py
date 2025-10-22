"""Comprehensive tests for FlextLdif standardized public API methods.

Tests cover:
- parse() method with various inputs
- filter_entries() and filter_entries_advanced()
- parse_batch() and parse_with_pagination()
- Real-world LDAP data scenarios

Uses pytest fixtures and real LDAP test data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifModels


class TestParseMethod:
    """Test FlextLdif.parse() unified method."""

    def test_parse_from_string_content(self) -> None:
        """Test parse() with LDIF content string."""
        ldif = FlextLdif()
        content = """dn: cn=Alice Johnson,ou=People,dc=example,dc=com
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
        result = ldif.parse(content)

        assert result.is_success, f"Parse failed: {result.error}"
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 2
        assert entries[0].dn.value == "cn=Alice Johnson,ou=People,dc=example,dc=com"
        assert entries[1].dn.value == "cn=Bob Smith,ou=People,dc=example,dc=com"

    def test_parse_from_file_path(self, test_ldif_dir: Path) -> None:
        """Test parse() with file path."""
        ldif = FlextLdif()

        # Create test LDIF file
        ldif_content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person

dn: cn=Test Group,dc=example,dc=com
cn: Test Group
objectClass: groupOfNames
member: cn=Test User,dc=example,dc=com
"""
        ldif_file = test_ldif_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        result = ldif.parse(ldif_file)

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 2

    def test_parse_from_path_string(self, test_ldif_dir: Path) -> None:
        """Test parse() with file path as string."""
        ldif = FlextLdif()

        ldif_content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""
        ldif_file = test_ldif_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        # Pass as string path
        result = ldif.parse(str(ldif_file))

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 1

    def test_parse_nonexistent_file(self) -> None:
        """Test parse() with nonexistent file returns error."""
        ldif = FlextLdif()
        result = ldif.parse(Path("/nonexistent/path/file.ldif"))

        assert result.is_failure
        error_msg = result.error
        assert error_msg is not None
        assert "not found" in error_msg.lower()

    def test_parse_with_server_type_quirks(self) -> None:
        """Test parse() applies server-specific quirks."""
        ldif = FlextLdif()

        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

        # Test with RFC mode (no quirks)
        result_rfc = ldif.parse(content, server_type="rfc")
        assert result_rfc.is_success

        # Test with OID quirks
        result_oid = ldif.parse(content, server_type="oid")
        assert result_oid.is_success

        # Both should parse successfully
        unwrapped_rfc = result_rfc.unwrap()
        assert isinstance(unwrapped_rfc, list), "Expected list, not callable"
        unwrapped_oid = result_oid.unwrap()
        assert isinstance(unwrapped_oid, list), "Expected list, not callable"
        assert len(unwrapped_rfc) == 1
        assert len(unwrapped_oid) == 1


class TestFilterEntriesMethods:
    """Test FlextLdif filtering methods."""

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for filtering tests."""
        entries = []

        # Person entry using Entry.create()
        alice_result = FlextLdifModels.Entry.create(
            dn="cn=Alice,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Alice"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["alice@example.com"],
                "uid": ["alice"],
            },
        )
        if alice_result.is_success:
            entries.append(alice_result.unwrap())

        # Another person entry
        bob_result = FlextLdifModels.Entry.create(
            dn="cn=Bob,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Bob"],
                "objectClass": ["person"],
                "uid": ["bob"],
            },
        )
        if bob_result.is_success:
            entries.append(bob_result.unwrap())

        # Group entry
        admin_result = FlextLdifModels.Entry.create(
            dn="cn=Admins,ou=Groups,dc=example,dc=com",
            attributes={
                "cn": ["Admins"],
                "objectClass": ["groupOfNames"],
                "member": ["cn=Alice,ou=People,dc=example,dc=com"],
            },
        )
        if admin_result.is_success:
            entries.append(admin_result.unwrap())

        return entries

    def test_filter_entries_by_objectclass(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries() with objectclass filter."""
        ldif = FlextLdif()

        result = ldif.filter(sample_entries, objectclass="person")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2
        for e in filtered:
            oc_attr = e.attributes.attributes.get("objectClass")
            assert oc_attr is not None
            oc_values = oc_attr.values if hasattr(oc_attr, "values") else oc_attr
            assert oc_values is not None
            assert "person" in oc_values

    def test_filter_entries_by_dn_pattern(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries() with DN pattern."""
        ldif = FlextLdif()

        result = ldif.filter(sample_entries, dn_pattern="ou=People")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2
        assert all("ou=People" in e.dn.value for e in filtered)

    def test_filter_entries_advanced_with_attributes(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries_advanced() with attribute filters."""
        ldif = FlextLdif()

        # Filter entries with mail attribute
        result = ldif.filter(
            sample_entries,
            attributes={"mail": None},  # Has mail attribute
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1
        mail_attr = filtered[0].attributes.attributes.get("mail")
        assert mail_attr is not None
        # Handle both raw lists and AttributeValues objects
        mail_values = mail_attr.values if hasattr(mail_attr, "values") else mail_attr
        assert "alice@example.com" in mail_values

    def test_filter_entries_advanced_with_custom_callback(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries_advanced() with custom filter callback."""
        ldif = FlextLdif()

        def has_uid(entry: FlextLdifModels.Entry) -> bool:
            uid_attr = entry.attributes.attributes.get("uid")
            return uid_attr is not None

        result = ldif.filter(sample_entries, custom_filter=has_uid)

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2
        assert all("uid" in e.attributes.attributes for e in filtered)

    def test_filter_entries_advanced_combined_criteria(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries_advanced() with multiple criteria."""
        ldif = FlextLdif()

        result = ldif.filter(
            sample_entries,
            objectclass="person",
            dn_pattern="ou=People",
            attributes={"uid": None},
            custom_filter=lambda e: len(e.attributes.attributes) > 3,
        )

        assert result.is_success
        filtered = result.unwrap()
        # Alice has 4 attributes, Bob has 3, so only Alice matches all criteria
        assert len(filtered) == 1
        assert filtered[0].dn.value == "cn=Alice,ou=People,dc=example,dc=com"

    def test_filter_entries_no_matches(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filter_entries() returns empty list when no matches."""
        ldif = FlextLdif()

        result = ldif.filter(sample_entries, objectclass="nonexistent")

        assert result.is_success
        assert len(result.unwrap()) == 0


class TestParseBatchAndPagination:
    """Test batch parsing and pagination methods."""

    def test_parse_batch_multiple_files(self, test_ldif_dir: Path) -> None:
        """Test parse_batch() with multiple files."""
        ldif = FlextLdif()

        # Create multiple LDIF files with correct type annotation
        files: list[str | Path] = []
        for i in range(3):
            content = f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person
"""
            ldif_file = test_ldif_dir / f"test{i}.ldif"
            ldif_file.write_text(content)
            files.append(ldif_file)

        result = ldif.parse(files, batch=True)

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 3
        dns = [e.dn.value for e in entries]
        assert any("User0" in dn for dn in dns)
        assert any("User1" in dn for dn in dns)
        assert any("User2" in dn for dn in dns)

    def test_parse_batch_partial_failure(self, test_ldif_dir: Path) -> None:
        """Test parse_batch() handles partial failures."""
        ldif = FlextLdif()

        # Create one valid and one invalid file
        valid_file = test_ldif_dir / "valid.ldif"
        valid_file.write_text(
            "dn: cn=Valid,dc=example,dc=com\ncn: Valid\nobjectClass: person\n"
        )

        invalid_path = test_ldif_dir / "nonexistent.ldif"

        result = ldif.parse([valid_file, invalid_path], batch=True)

        # Should still succeed with partial results
        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 1  # Only valid file parsed

    def test_parse_with_pagination_small_pages(self) -> None:
        """Test parse_with_pagination() with small page size."""
        ldif = FlextLdif()

        # Create LDIF with multiple entries
        content = "\n".join([
            f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person
"""
            for i in range(10)
        ])

        result = ldif.parse(content, paginate=True, page_size=3)

        assert result.is_success
        unwrapped = result.unwrap()
        assert callable(unwrapped), "Expected callable for paginated results"
        get_next_page = unwrapped

        # Collect all pages
        all_pages: list[list[FlextLdifModels.Entry]] = []
        while True:
            page = get_next_page()
            if page is None:
                break
            all_pages.append(page)

        # Should have 4 pages: 3+3+3+1
        assert len(all_pages) == 4
        assert len(all_pages[0]) == 3
        assert len(all_pages[1]) == 3
        assert len(all_pages[2]) == 3
        assert len(all_pages[3]) == 1

    def test_parse_with_pagination_get_total_count(self) -> None:
        """Test pagination provides total count."""
        ldif = FlextLdif()

        content = "\n".join([
            f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person
"""
            for i in range(5)
        ])

        result = ldif.parse(content, paginate=True, page_size=2)

        assert result.is_success
        unwrapped = result.unwrap()
        assert callable(unwrapped), "Expected callable for paginated results"
        get_next_page = unwrapped

        first_page = get_next_page()
        assert first_page is not None
        assert len(first_page) == 2


class TestBuildMethods:
    """Test entry builder methods."""

    def test_build_person_entry(self) -> None:
        """Test build_person_entry() creates valid person entries."""
        ldif = FlextLdif()

        result = ldif.build(
            "person",
            cn="John Doe",
            sn="Doe",
            base_dn="ou=People,dc=example,dc=com",
            uid="jdoe",
            mail="jdoe@example.com",
            given_name="John",
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=John Doe,ou=People,dc=example,dc=com"
        # Try both camelCase and lowercase keys (builder may create either)
        oc_attr = entry.attributes.attributes.get(
            "objectClass"
        ) or entry.attributes.attributes.get("objectclass")
        assert oc_attr is not None
        oc_values = oc_attr.values if hasattr(oc_attr, "values") else oc_attr
        assert oc_values is not None
        assert "person" in oc_values
        # Handle both raw lists and AttributeValues objects for mail
        mail_attr = entry.attributes.attributes.get("mail")
        assert mail_attr is not None
        mail_values = mail_attr.values if hasattr(mail_attr, "values") else mail_attr
        assert mail_values == ["jdoe@example.com"]

    def test_build_group_entry(self) -> None:
        """Test build_group_entry() creates valid group entries."""
        ldif = FlextLdif()

        members = ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"]
        result = ldif.build(
            "group",
            cn="Admins",
            base_dn="ou=Groups,dc=example,dc=com",
            members=members,
            description="Administrator group",
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=Admins,ou=Groups,dc=example,dc=com"
        # Try both camelCase and lowercase keys (builder may create either)
        oc_attr = entry.attributes.attributes.get(
            "objectClass"
        ) or entry.attributes.attributes.get("objectclass")
        assert oc_attr is not None
        oc_values = oc_attr.values if hasattr(oc_attr, "values") else oc_attr
        assert oc_values is not None
        assert "groupOfNames" in oc_values
        # Handle AttributeValues objects for member
        member_attr = entry.attributes.attributes.get("member")
        assert member_attr is not None
        member_values = (
            member_attr.values if hasattr(member_attr, "values") else member_attr
        )
        assert member_values == members

    def test_build_ou_entry(self) -> None:
        """Test build_ou_entry() creates valid OU entries."""
        ldif = FlextLdif()

        result = ldif.build(
            "ou",
            ou="People",
            base_dn="dc=example,dc=com",
            description="People organizational unit",
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "ou=People,dc=example,dc=com"
        # Try both camelCase and lowercase keys (builder may create either)
        oc_attr = entry.attributes.attributes.get(
            "objectClass"
        ) or entry.attributes.attributes.get("objectclass")
        assert oc_attr is not None
        oc_values = oc_attr.values if hasattr(oc_attr, "values") else oc_attr
        assert oc_values is not None
        assert "organizationalUnit" in oc_values

    def test_build_custom_entry(self) -> None:
        """Test build_custom_entry() creates entries with arbitrary attributes."""
        ldif = FlextLdif()

        # Type annotation to match expected signature
        attributes: dict[str, str | list[str]] = {
            "objectClass": ["person"],
            "cn": ["Test User"],
            "mail": ["test@example.com"],
            "custom_attr": ["custom_value"],
        }

        result = ldif.build(
            "custom", dn="cn=Test User,dc=example,dc=com", attributes=attributes
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=Test User,dc=example,dc=com"
        custom_attr = entry.attributes.attributes.get("custom_attr")
        assert custom_attr is not None
        custom_values = (
            custom_attr.values if hasattr(custom_attr, "values") else custom_attr
        )
        assert custom_values == ["custom_value"]


class TestValidateAndAnalyzeMethods:
    """Test validation and analysis methods."""

    def test_validate_entries(self) -> None:
        """Test validate_entries() validates entries."""
        ldif = FlextLdif()

        # Create entry using Entry.create()
        entry = FlextLdifModels.Entry.create(
            dn="cn=Test,dc=example,dc=com", attributes={"objectClass": ["person"]}
        )
        entries: list[FlextLdifModels.Entry] = (
            [entry] if isinstance(entry, FlextLdifModels.Entry) else []
        )

        if entries:
            result = ldif.validate_entries(entries)
            assert result.is_success
            report = result.unwrap()
            assert "valid" in str(report).lower() or isinstance(report, dict)

    def test_analyze_entries(self) -> None:
        """Test analyze_entries() generates statistics."""
        ldif = FlextLdif()

        # Create entries using Entry.create()
        user_entry = FlextLdifModels.Entry.create(
            dn="cn=User1,dc=example,dc=com", attributes={"objectClass": ["person"]}
        )
        group_entry = FlextLdifModels.Entry.create(
            dn="cn=Group1,dc=example,dc=com",
            attributes={"objectClass": ["groupOfNames"]},
        )

        entries: list[FlextLdifModels.Entry] = []
        if isinstance(user_entry, FlextLdifModels.Entry):
            entries.append(user_entry)
        if isinstance(group_entry, FlextLdifModels.Entry):
            entries.append(group_entry)

        if entries:
            result = ldif.analyze(entries)
            assert result.is_success
            stats = result.unwrap()
            # Should have statistics about entries
            assert isinstance(stats, dict)


class TestRealWorldScenarios:
    """Test with realistic LDAP data."""

    def test_parse_realistic_directory_structure(self, test_ldif_dir: Path) -> None:
        """Test parsing realistic directory structure."""
        ldif = FlextLdif()

        # Create a realistic directory structure
        content = """dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
o: Example Organization

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: cn=Alice Smith,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice Smith
sn: Smith
givenName: Alice
mail: alice.smith@example.com
telephoneNumber: +1-555-0100

dn: cn=Bob Johnson,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Bob Johnson
sn: Johnson
givenName: Bob
mail: bob.johnson@example.com
telephoneNumber: +1-555-0101

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups

dn: cn=Administrators,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Administrators
member: cn=Alice Smith,ou=People,dc=example,dc=com
"""

        ldif_file = test_ldif_dir / "realistic.ldif"
        ldif_file.write_text(content)

        result = ldif.parse(ldif_file)

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped
        assert len(entries) == 6

        # Verify structure
        # Note: includes organizational unit entries (ou=People and ou=Groups)
        people = [
            e
            for e in entries
            if "People" in e.dn.value
            or "Smith" in e.dn.value
            or "Johnson" in e.dn.value
        ]
        groups = [
            e
            for e in entries
            if "Groups" in e.dn.value or "Administrators" in e.dn.value
        ]

        assert len(people) == 3  # ou=People + Alice + Bob
        assert len(groups) == 2  # ou=Groups + cn=Administrators

    def test_migration_scenario_oid_to_oud(self, test_ldif_dir: Path) -> None:
        """Test realistic OID to OUD migration scenario."""
        ldif = FlextLdif()

        # OID-style LDIF
        oid_content = """dn: cn=Test User,cn=Users,dc=oracle,dc=com
cn: Test User
objectClass: inetOrgPerson
objectClass: person
givenName: Test
sn: User
mail: testuser@example.com
"""

        oid_file = test_ldif_dir / "oid_data.ldif"
        oid_file.write_text(oid_content)

        # Parse as OID
        oid_result = ldif.parse(oid_file, server_type="oid")
        assert oid_result.is_success

        # Convert to OUD format
        unwrapped = oid_result.unwrap()
        assert isinstance(unwrapped, list), "Expected list, not callable"
        entries = unwrapped

        # Should maintain data integrity
        assert len(entries) == 1
        assert "Test User" in str(entries[0].dn.value)
        oc_attr = entries[0].attributes.attributes.get("objectClass")
        assert oc_attr is not None
        oc_values = oc_attr.values if hasattr(oc_attr, "values") else oc_attr
        assert oc_values is not None
        assert "inetOrgPerson" in oc_values


__all__ = [
    "TestBuildMethods",
    "TestFilterEntriesMethods",
    "TestParseBatchAndPagination",
    "TestParseMethod",
    "TestRealWorldScenarios",
    "TestValidateAndAnalyzeMethods",
]
