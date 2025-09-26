"""Integration tests for example scripts execution.

Tests that example scripts execute correctly using real API calls.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig


class TestBasicParsingExample:
    """Test 01_basic_parsing.py example execution."""

    @staticmethod
    def test_basic_parsing_example_execution(test_ldif_dir: Path) -> None:
        """Test basic parsing example workflow logic."""
        sample_ldif = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
mail: john@example.com
objectClass: person
objectClass: inetOrgPerson

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
mail: jane@example.com
objectClass: person
objectClass: inetOrgPerson

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit
"""
        sample_file = test_ldif_dir / "sample_basic.ldif"
        sample_file.write_text(sample_ldif, encoding="utf-8")

        config = FlextLdifConfig(
            ldif_strict_validation=True,
            ldif_max_entries=1000,
            ldif_chunk_size=1000,
            enable_performance_optimizations=False,
        )
        api = FlextLdifAPI(config)

        result = api.parse_ldif_file(sample_file)
        assert result.is_success
        entries = result.value
        assert len(entries) == 3

        stats_result = api.entry_statistics(entries)
        assert stats_result.is_success

        first_entry = entries[0]
        validation_result = first_entry.validate_business_rules()
        assert validation_result.is_success

        person_result = api.filter_persons(entries)
        assert person_result.is_success
        person_entries = person_result.value
        assert len(person_entries) == 2

        output_file = test_ldif_dir / "output_basic.ldif"
        write_result = api.write_file(person_entries, str(output_file))
        assert write_result.is_success
        assert output_file.exists()

        output_content = output_file.read_text(encoding="utf-8")
        assert "cn=John Doe" in output_content
        assert "cn=Jane Smith" in output_content

    @staticmethod
    def test_basic_parsing_workflow_without_mock(test_ldif_dir: Path) -> None:
        """Test basic parsing workflow using real API."""
        sample_ldif = """dn: cn=Test User,dc=example,dc=com
cn: Test User
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
"""
        sample_file = test_ldif_dir / "test_sample.ldif"
        sample_file.write_text(sample_ldif, encoding="utf-8")

        api = FlextLdifAPI()
        result = api.parse_ldif_file(sample_file)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

        person_result = api.filter_persons(entries)
        assert person_result.is_success
        person_entries = person_result.value
        assert len(person_entries) == 1

        output_file = test_ldif_dir / "output_test.ldif"
        write_result = api.write_file(person_entries, str(output_file))
        assert write_result.is_success
        assert output_file.exists()


class TestDockerExample:
    """Test 04_simple_docker_test.py example execution."""

    @staticmethod
    def test_docker_example_without_docker() -> None:
        """Test docker example logic without actual Docker."""
        ldif_data = """dn: cn=Test Person,dc=example,dc=com
cn: Test Person
sn: Person
objectClass: person
objectClass: inetOrgPerson

dn: ou=Groups,dc=example,dc=com
ou: Groups
objectClass: organizationalUnit
"""

        api = FlextLdifAPI()
        parse_result = api.parse(ldif_data)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 2

        validate_result = api.validate_entries(entries)
        assert validate_result.is_success

        person_filter_result = api.filter_persons(entries)
        assert person_filter_result.is_success
        person_entries = person_filter_result.unwrap()
        assert len(person_entries) == 1

        group_count = sum(
            1
            for entry in entries
            if hasattr(entry, "is_group_entry") and entry.is_group_entry()
        )
        assert group_count == 0

        ou_count = sum(
            1
            for entry in entries
            if hasattr(entry, "is_organizational_unit")
            and entry.is_organizational_unit()
        )
        assert ou_count == 1

    @staticmethod
    def test_docker_example_entry_attributes() -> None:
        """Test docker example entry attribute access."""
        ldif_data = """dn: cn=John Doe,dc=example,dc=com
cn: John Doe
sn: Doe
mail: john@example.com
objectClass: person
objectClass: inetOrgPerson
"""

        api = FlextLdifAPI()
        parse_result = api.parse(ldif_data)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 1

        entry = entries[0]
        assert hasattr(entry, "has_attribute")
        assert entry.has_attribute("cn")
        assert entry.has_attribute("mail")
        assert entry.has_attribute("objectClass")

        cn_value = entry.get_single_value("cn")
        assert cn_value == "John Doe"

        mail_value = entry.get_single_value("mail")
        assert mail_value == "john@example.com"
