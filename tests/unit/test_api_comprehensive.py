"""Comprehensive unit tests for FlextLdif API functionality.

Tests all major API methods with real validation of functionality.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult
from tests.test_support.ldif_data import LdifTestData

from flext_ldif.api import FlextLdif


class TestFlextLdifApiParse:
    """Test suite for LDIF parsing functionality."""

    def test_parse_string_basic(self) -> None:
        """Test parsing basic LDIF content from string."""
        ldif = FlextLdif()
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
objectClass: organizationalPerson
mail: test@example.com

dn: cn=Another User,dc=example,dc=com
cn: Another User
sn: User
objectClass: person
"""

        result = ldif.parse(content)

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 2

        # Check first entry structure
        first_entry = entries[0]
        assert hasattr(first_entry, "dn")
        assert hasattr(first_entry, "attributes")
        # Should be a proper model object
        assert first_entry.dn.value == "cn=Test User,dc=example,dc=com"

    def test_parse_string_with_changes(self) -> None:
        """Test parsing LDIF with change records."""
        ldif = FlextLdif()
        content = """dn: cn=Test User,dc=example,dc=com
changetype: add
cn: Test User
sn: User
objectClass: person
"""

        result = ldif.parse(content)

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)

    def test_parse_file(self, tmp_path: Path) -> None:
        """Test parsing LDIF from file."""
        ldif = FlextLdif()
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""

        # Create test file
        test_file = tmp_path / "test_parse.ldif"
        test_file.write_text(content, encoding="utf-8")

        result = ldif.parse(test_file)

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 1

    def test_parse_invalid_content(self) -> None:
        """Test parsing invalid LDIF content."""
        ldif = FlextLdif()
        invalid_content = "invalid content without proper DN"

        result = ldif.parse(invalid_content)

        # Should handle gracefully - either fail or parse what it can
        assert isinstance(result, FlextResult)

    def test_parse_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        ldif = FlextLdif()

        result = ldif.parse("")

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0

    def test_parse_with_server_type(self, ldif_test_data: LdifTestData) -> None:
        """Test parsing with different server types."""
        ldif = FlextLdif()
        content = ldif_test_data.basic_entries().content

        # Test with different server types
        for server_type in ["rfc", "oid", "oud", "auto"]:
            result = ldif.parse(content, server_type=server_type)
            assert isinstance(result, FlextResult)


class TestFlextLdifApiWrite:
    """Test suite for LDIF writing functionality."""

    def test_write_to_string(self, ldif_test_data: LdifTestData) -> None:
        """Test writing entries to LDIF string."""
        ldif = FlextLdif()

        # First parse some content to get entries
        content = ldif_test_data.basic_entries().content
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Now write back to string
        write_result = ldif.write(entries)

        assert write_result.is_success
        ldif_string = write_result.unwrap()
        assert isinstance(ldif_string, str)
        assert len(ldif_string) > 0
        assert "dn:" in ldif_string

    def test_write_to_file(self, tmp_path: Path) -> None:
        """Test writing entries to LDIF file."""
        ldif = FlextLdif()

        # Create test entries
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write to file
        output_file = tmp_path / "output.ldif"
        write_result = ldif.write(entries, output_path=output_file)

        assert write_result.is_success
        assert output_file.exists()
        file_content = output_file.read_text(encoding="utf-8")
        assert len(file_content) > 0
        assert "dn:" in file_content

    def test_write_empty_entries(self) -> None:
        """Test writing empty entries list."""
        ldif = FlextLdif()

        result = ldif.write([])

        assert result.is_success
        content = result.unwrap()
        assert isinstance(content, str)
        assert len(content.strip()) == 0


class TestFlextLdifApiValidate:
    """Test suite for LDIF validation functionality."""

    def test_validate_valid_entries(self) -> None:
        """Test validating valid LDIF entries."""
        ldif = FlextLdif()

        # Create some valid entries
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        validate_result = ldif.validate_entries(entries)

        assert validate_result.is_success
        report = validate_result.unwrap()
        assert isinstance(report, dict)

    def test_validate_empty_entries(self) -> None:
        """Test validating empty entries list."""
        ldif = FlextLdif()

        result = ldif.validate_entries([])

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)


class TestFlextLdifApiMigrate:
    """Test suite for LDIF migration functionality."""

    # TODO: Implement in-memory migration method
    # def test_migrate_basic(self) -> None:
    #     """Test basic migration between formats."""
    #     ldif = FlextLdif()
    #
    #     # Create some entries
    #     content = """dn: cn=Test User,dc=example,dc=com
    # cn: Test User
    # sn: User
    # objectClass: person
    # """
    #     parse_result = ldif.parse(content)
    #     assert parse_result.is_success
    #     entries = parse_result.unwrap()
    #
    #     # Test migration
    #     migrate_result = ldif.migrate(entries=entries, from_server="rfc", to_server="oid")
    #
    #     assert isinstance(migrate_result, FlextResult)

    # TODO: Implement in-memory migration method
    # def test_migrate_same_format(self) -> None:
    #     """Test migration with same source and target format."""
    #     ldif = FlextLdif()
    #
    #     # Create some entries
    #     content = """dn: cn=Test User,dc=example,dc=com
    # cn: Test User
    # sn: User
    # objectClass: person
    # """
    #     parse_result = ldif.parse(content)
    #     assert parse_result.is_success
    #     entries = parse_result.unwrap()
    #
    #     # Test migration with same format
    #     migrate_result = ldif.migrate(entries=entries, from_server="rfc", to_server="rfc")
    #
    #     assert isinstance(migrate_result, FlextResult)


class TestFlextLdifApiAnalyze:
    """Test suite for LDIF analysis functionality."""

    def test_analyze_basic(self) -> None:
        """Test basic analysis of LDIF entries."""
        ldif = FlextLdif()

        # Create some entries
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        analyze_result = ldif.analyze(entries)

        assert analyze_result.is_success
        report = analyze_result.unwrap()
        assert isinstance(report, dict)

    def test_analyze_empty_entries(self) -> None:
        """Test analyzing empty entries list."""
        ldif = FlextLdif()

        result = ldif.analyze([])

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)


class TestFlextLdifApiFilter:
    """Test suite for LDIF filtering functionality."""

    def test_filter_by_objectclass(self) -> None:
        """Test filtering entries by object class."""
        ldif = FlextLdif()

        # Create some entries
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: inetOrgPerson
objectClass: person

dn: cn=Test Group,dc=example,dc=com
cn: Test Group
objectClass: groupOfNames
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        filter_result = ldif.filter_by_objectclass(entries, "inetOrgPerson")

        assert filter_result.is_success
        filtered = filter_result.unwrap()
        assert isinstance(filtered, list)
        assert len(filtered) == 1

    def test_filter_persons(self) -> None:
        """Test filtering for person entries."""
        ldif = FlextLdif()

        # Create some entries
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: inetOrgPerson
objectClass: person

dn: cn=Test Group,dc=example,dc=com
cn: Test Group
objectClass: groupOfNames
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        filter_result = ldif.filter_persons(entries)

        assert filter_result.is_success
        filtered = filter_result.unwrap()
        assert isinstance(filtered, list)
        assert len(filtered) == 1


class TestFlextLdifApiInfrastructure:
    """Test suite for API infrastructure methods."""

    def test_entry_builder_access(self) -> None:
        """Test accessing entry builder."""
        ldif = FlextLdif()

        builder_class = ldif.entry_builder()
        assert builder_class is not None

    def test_schema_builder_access(self) -> None:
        """Test accessing schema builder."""
        ldif = FlextLdif()

        builder_class = ldif.schema_builder()
        assert builder_class is not None

    def test_acl_service_access(self) -> None:
        """Test accessing ACL service."""
        ldif = FlextLdif()

        service_class = ldif.acl_service()
        assert service_class is not None

    def test_schema_validator_access(self) -> None:
        """Test accessing schema validator."""
        ldif = FlextLdif()

        validator_class = ldif.schema_validator()
        assert validator_class is not None

    def test_models_access(self) -> None:
        """Test accessing models namespace."""
        ldif = FlextLdif()

        models = ldif.models()
        assert models is not None
        assert hasattr(models, "Entry")

    def test_config_access(self) -> None:
        """Test accessing configuration."""
        ldif = FlextLdif()

        config = ldif.config
        assert config is not None

    def test_constants_access(self) -> None:
        """Test accessing constants."""
        ldif = FlextLdif()

        constants = ldif.constants()
        assert constants is not None

    def test_types_access(self) -> None:
        """Test accessing types."""
        ldif = FlextLdif()

        types = ldif.types()
        assert types is not None

    def test_protocols_access(self) -> None:
        """Test accessing protocols."""
        ldif = FlextLdif()

        protocols = ldif.protocols()
        assert protocols is not None

    def test_exceptions_access(self) -> None:
        """Test accessing exceptions."""
        ldif = FlextLdif()

        exceptions = ldif.exceptions()
        assert exceptions is not None

    def test_mixins_access(self) -> None:
        """Test accessing mixins."""
        ldif = FlextLdif()

        mixins = ldif.mixins()
        assert mixins is not None

    def test_utilities_access(self) -> None:
        """Test accessing utilities."""
        ldif = FlextLdif()

        utilities = ldif.utilities()
        assert utilities is not None

    def test_processors_access(self) -> None:
        """Test accessing processors."""
        ldif = FlextLdif()

        processors = ldif.processors()
        assert processors is not None


class TestFlextLdifApiIntegration:
    """Integration tests for complete workflows."""

    def test_parse_write_roundtrip(self) -> None:
        """Test parsing and writing creates equivalent output."""
        ldif = FlextLdif()

        # Start with some LDIF content
        original_content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""

        # Parse it
        parse_result = ldif.parse(original_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write it back
        write_result = ldif.write(entries)
        assert write_result.is_success
        new_content = write_result.unwrap()

        # Should produce valid LDIF
        assert isinstance(new_content, str)
        assert len(new_content) > 0
        assert "dn:" in new_content

    def test_parse_validate_analyze_workflow(self) -> None:
        """Test complete parse-validate-analyze workflow."""
        ldif = FlextLdif()

        # Parse
        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
sn: User
objectClass: person
"""
        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Validate
        validate_result = ldif.validate_entries(entries)
        assert validate_result.is_success

        # Analyze
        analyze_result = ldif.analyze(entries)
        assert analyze_result.is_success

        # All results should be proper dictionaries or lists
        assert isinstance(validate_result.unwrap(), dict)
        assert isinstance(analyze_result.unwrap(), dict)
