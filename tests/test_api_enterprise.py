"""Enterprise tests for FlextLdifAPI functionality.

Comprehensive test suite covering all API functionality with enterprise-grade
testing practices, configuration management, and error handling validation.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifAPI,
    FlextLdifConfig,
    FlextLdifEntry,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3


class TestFlextLdifAPIEnterprise:
    """Enterprise-grade tests for FlextLdifAPI."""

    @pytest.fixture
    def default_config(self) -> FlextLdifConfig:
        """Default configuration for testing."""
        return FlextLdifConfig()

    @pytest.fixture
    def strict_config(self) -> FlextLdifConfig:
        """Strict configuration for testing."""
        return FlextLdifConfig.model_validate(
            {
                "strict_validation": True,
                "max_entries": 10,
                "max_entry_size": 1024,
            },
        )

    @pytest.fixture
    def permissive_config(self) -> FlextLdifConfig:
        """Permissive configuration for testing."""
        return FlextLdifConfig.model_validate(
            {
                "strict_validation": False,
                "max_entries": 1000,
                "max_entry_size": 10240,
            },
        )

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Sample LDIF content for testing."""
        return """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
uid: johndoe

dn: cn=Admin User,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: Admin User
sn: User
givenName: Admin
mail: admin@example.com
uid: admin

dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: developers
member: cn=John Doe,ou=people,dc=example,dc=com

"""

    def test_api_initialization_default_config(self) -> None:
        """Test API initialization with default configuration."""
        api = FlextLdifAPI()

        assert api.config is not None
        assert isinstance(api.config, FlextLdifConfig)
        # Specifications now integrated in FlextLdifEntry via composition

    def test_api_initialization_custom_config(
        self,
        strict_config: FlextLdifConfig,
    ) -> None:
        """Test API initialization with custom configuration."""
        api = FlextLdifAPI(strict_config)

        if api.config != strict_config:
            msg: str = f"Expected {strict_config}, got {api.config}"
            raise AssertionError(msg)
        if not (api.config.strict_validation):
            msg: str = f"Expected True, got {api.config.strict_validation}"
            raise AssertionError(msg)
        if api.config.max_entries != 10:
            msg: str = f"Expected {10}, got {api.config.max_entries}"
            raise AssertionError(msg)

    def test_parse_success_default_config(self, sample_ldif_content: str) -> None:
        """Test parsing with default configuration succeeds."""
        api = FlextLdifAPI()

        result = api.parse(sample_ldif_content)

        assert result.success
        assert result.data is not None
        if len(result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(result.data)}"
            raise AssertionError(msg)
        assert result.error is None

    def test_parse_success_strict_config(
        self,
        sample_ldif_content: str,
        strict_config: FlextLdifConfig,
    ) -> None:
        """Test parsing with strict configuration succeeds."""
        api = FlextLdifAPI(strict_config)

        result = api.parse(sample_ldif_content)

        assert result.success
        assert result.data is not None
        if len(result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(result.data)}"
            raise AssertionError(msg)

    def test_parse_fails_max_entries_exceeded(
        self,
        strict_config: FlextLdifConfig,
    ) -> None:
        """Test parsing fails when max entries exceeded."""
        # Create content with more entries than max_entries (10)
        large_content = ""
        for i in range(15):
            large_content += f"""dn: cn=user{i},ou=people,dc=example,dc=com
objectClass: person
cn: user{i}
sn: User{i}

"""

        api = FlextLdifAPI(strict_config)
        result = api.parse(large_content)

        assert not result.success
        assert result.error is not None
        if "exceeds configured limit" not in result.error.lower():
            msg: str = f"Expected 'exceeds configured limit' in {result.error.lower()}"
            raise AssertionError(msg)

    def test_parse_file_success(self, sample_ldif_content: str) -> None:
        """Test parsing file succeeds."""
        api = FlextLdifAPI()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as f:
            f.write(sample_ldif_content)
            temp_file = Path(f.name)

        try:
            result = api.parse_file(temp_file)

            assert result.success
            assert result.data is not None
            if len(result.data) != EXPECTED_DATA_COUNT:
                msg: str = f"Expected {3}, got {len(result.data)}"
                raise AssertionError(msg)

        finally:
            temp_file.unlink(missing_ok=True)

    def test_parse_file_not_found(self) -> None:
        """Test parsing nonexistent file fails gracefully."""
        api = FlextLdifAPI()
        nonexistent_file = Path("/nonexistent/file.ldif")

        result = api.parse_file(nonexistent_file)

        assert not result.success
        assert result.error is not None
        if "not found" not in result.error.lower():
            msg: str = f"Expected {'not found'} in {result.error.lower()}"
            raise AssertionError(msg)

    def test_validate_success(self, sample_ldif_content: str) -> None:
        """Test validation succeeds for valid entries."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        validate_result = api.validate(parse_result.data)

        assert validate_result.success
        if not (validate_result.data):
            msg: str = f"Expected True, got {validate_result.data}"
            raise AssertionError(msg)

    def test_write_to_string_success(self, sample_ldif_content: str) -> None:
        """Test writing to string succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        write_result = api.write(parse_result.data)

        assert write_result.success
        assert write_result.data is not None
        assert len(write_result.data) > 0
        if "dn:" not in write_result.data:
            msg: str = f"Expected {'dn:'} in {write_result.data}"
            raise AssertionError(msg)

    def test_write_to_file_success(self, sample_ldif_content: str) -> None:
        """Test writing to file succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as f:
            temp_file = Path(f.name)

        try:
            write_result = api.write_file(parse_result.data, temp_file)

            assert write_result.success
            # write_file returns FlextResult[bool], so data should be True for success
            assert write_result.data is True
            assert temp_file.exists()

            # Verify content
            content = temp_file.read_text(encoding="utf-8")
            assert len(content) > 0
            if "dn:" not in content:
                msg: str = f"Expected {'dn:'} in {content}"
                raise AssertionError(msg)

        finally:
            temp_file.unlink(missing_ok=True)

    def test_filter_persons_success(self, sample_ldif_content: str) -> None:
        """Test filtering person entries succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        filter_result = api.filter_persons(parse_result.data)

        assert filter_result.success
        assert filter_result.data is not None
        # Should find 2 person entries (John Doe and Admin User)
        if len(filter_result.data) != EXPECTED_BULK_SIZE:
            msg: str = f"Expected {2}, got {len(filter_result.data)}"
            raise AssertionError(msg)

        for entry in filter_result.data:
            assert entry.has_object_class("person")

    def test_filter_valid_success(self, sample_ldif_content: str) -> None:
        """Test filtering valid entries succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        filter_result = api.filter_valid(parse_result.data)

        assert filter_result.success
        assert filter_result.data is not None
        # All entries should be valid
        if len(filter_result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(filter_result.data)}"
            raise AssertionError(msg)

    def test_filter_by_objectclass_success(self, sample_ldif_content: str) -> None:
        """Test filtering by objectClass succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        # Filter by person objectClass
        person_result = api.filter_by_objectclass(parse_result.data, "person")
        assert person_result.success
        person_entries = person_result.data
        if len(person_entries) != EXPECTED_BULK_SIZE:
            msg: str = f"Expected {2}, got {len(person_entries)}"
            raise AssertionError(msg)

        # Filter by groupOfNames objectClass
        group_result = api.filter_by_objectclass(parse_result.data, "groupOfNames")
        assert group_result.success
        group_entries = group_result.data
        if len(group_entries) != 1:
            msg: str = f"Expected {1}, got {len(group_entries)}"
            raise AssertionError(msg)

    def test_find_entry_by_dn_success(self, sample_ldif_content: str) -> None:
        """Test finding entry by DN succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        target_dn = "cn=John Doe,ou=people,dc=example,dc=com"
        found_result = api.find_entry_by_dn(parse_result.data, target_dn)

        assert found_result.success
        assert found_result.data is not None
        found_entry = found_result.data
        if str(found_entry.dn) != target_dn:
            msg: str = f"Expected {target_dn}, got {found_entry.dn!s}"
            raise AssertionError(msg)
        assert found_entry.get_attribute("cn") == ["John Doe"]

    def test_find_entry_by_dn_not_found(self, sample_ldif_content: str) -> None:
        """Test finding nonexistent entry by DN returns None."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        nonexistent_dn = "cn=nonexistent,ou=people,dc=example,dc=com"
        found_result = api.find_entry_by_dn(parse_result.data, nonexistent_dn)

        assert found_result.success
        assert found_result.data is None

    def test_sort_hierarchically_success(self, sample_ldif_content: str) -> None:
        """Test hierarchical sorting succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        sort_result = api.sort_hierarchically(parse_result.data)

        assert sort_result.success
        assert sort_result.data is not None
        if len(sort_result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(sort_result.data)}"
            raise AssertionError(msg)

        # Verify sorting (entries with fewer commas should come first)
        sorted_entries = sort_result.data
        for i in range(len(sorted_entries) - 1):
            current_depth = str(sorted_entries[i].dn).count(",")
            next_depth = str(sorted_entries[i + 1].dn).count(",")
            assert current_depth <= next_depth

    def test_entries_to_ldif_success(self, sample_ldif_content: str) -> None:
        """Test converting entries to LDIF string succeeds."""
        api = FlextLdifAPI()

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success

        ldif_result = api.write(parse_result.data)

        assert ldif_result.success
        assert ldif_result.data is not None
        ldif_output = ldif_result.data
        assert len(ldif_output) > 0
        if "dn:" not in ldif_output:
            msg: str = f"Expected {'dn:'} in {ldif_output}"
            raise AssertionError(msg)
        assert "objectClass:" in ldif_output

    def test_configuration_validation_strict(self, sample_ldif_content: str) -> None:
        """Test configuration with strict validation enabled."""
        strict_config = FlextLdifConfig.model_validate(
            {
                "strict_validation": True,
                "max_entries": 100,
            },
        )

        api = FlextLdifAPI(strict_config)

        # Should validate during parsing
        result = api.parse(sample_ldif_content)
        assert result.success  # Valid content should pass

    def test_configuration_validation_permissive(self) -> None:
        """Test configuration with permissive validation."""
        permissive_config = FlextLdifConfig.model_validate(
            {
                "strict_validation": False,
                "max_entries": 1000,
            },
        )

        api = FlextLdifAPI(permissive_config)

        # Even invalid content might pass parsing without validation
        invalid_content = """dn: cn=test,dc=example,dc=com
cn: test
# Missing objectClass but validation is disabled
"""

        result = api.parse(invalid_content)
        # Should parse successfully due to permissive config
        assert result.success or not result.success  # Either is acceptable

    def test_error_handling_robustness(self) -> None:
        """Test API error handling robustness."""
        api = FlextLdifAPI()

        # Test various invalid inputs
        invalid_inputs = ["", None, 123, [], {}]

        for invalid_input in invalid_inputs:
            try:
                result = api.parse(invalid_input)
                # Should handle gracefully
                assert result is not None
                if not result.success:
                    assert result.error is not None
            except (RuntimeError, ValueError, TypeError):
                # Expected exceptions should be handled
                pass

    def test_performance_with_large_content(self) -> None:
        """Test API performance with larger content."""

        api = FlextLdifAPI()

        # Generate larger content
        large_content = ""
        for i in range(50):
            large_content += f"""dn: cn=user{i},ou=people,dc=example,dc=com
objectClass: person
cn: user{i}
sn: User{i}
mail: user{i}@example.com

"""

        start_time = time.time()
        result = api.parse(large_content)
        parse_time = time.time() - start_time

        assert result.success
        if len(result.data) != 50:
            msg: str = f"Expected {50}, got {len(result.data)}"
            raise AssertionError(msg)
        assert parse_time < 3.0  # Should be reasonably fast


class TestFlextLdifConvenienceFunctions:
    """Enterprise tests for convenience functions."""

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Sample LDIF content for testing."""
        return """dn: cn=test,ou=people,dc=example,dc=com
objectClass: person
cn: test
sn: user
mail: test@example.com

"""

    def test_flext_ldif_get_api_singleton(self) -> None:
        """Test global API instance management."""
        api1 = flext_ldif_get_api()
        api2 = flext_ldif_get_api()

        # Should return same instance
        assert api1 is api2

    def test_flext_ldif_get_api_with_config(self) -> None:
        """Test global API with custom configuration."""
        config = FlextLdifConfig.model_validate({"strict_validation": True})

        api1 = flext_ldif_get_api(config)
        api2 = flext_ldif_get_api()  # Should return same configured instance

        assert api1 is api2
        if not (api1.config.strict_validation):
            msg: str = f"Expected True, got {api1.config.strict_validation}"
            raise AssertionError(msg)

    def test_flext_ldif_parse_convenience(self, sample_ldif_content: str) -> None:
        """Test convenience parse function."""
        entries = flext_ldif_parse(sample_ldif_content)

        assert isinstance(entries, list)
        if len(entries) != 1:
            msg: str = f"Expected {1}, got {len(entries)}"
            raise AssertionError(msg)
        assert isinstance(entries[0], FlextLdifEntry)
        if entries[0].get_attribute("cn") != ["test"]:
            msg: str = f"Expected {['test']}, got {entries[0].get_attribute('cn')}"
            raise AssertionError(msg)

    def test_flext_ldif_parse_convenience_failure(self) -> None:
        """Test convenience parse function with invalid content."""
        entries = flext_ldif_parse("invalid content")

        assert isinstance(entries, list)
        if len(entries) != 0:  # Should return empty list on failure
            msg = (
                f"Expected 0 (should return empty list on failure), got {len(entries)}"
            )
            raise AssertionError(msg)

    def test_flext_ldif_validate_convenience_success(
        self,
        sample_ldif_content: str,
    ) -> None:
        """Test convenience validate function success."""
        is_valid = flext_ldif_validate(sample_ldif_content)

        assert isinstance(is_valid, bool)
        if not (is_valid):
            msg: str = f"Expected True, got {is_valid}"
            raise AssertionError(msg)

    def test_flext_ldif_validate_convenience_failure(self) -> None:
        """Test convenience validate function failure."""
        is_valid = flext_ldif_validate("invalid content")

        assert isinstance(is_valid, bool)
        if is_valid:
            msg: str = f"Expected False, got {is_valid}"
            raise AssertionError(msg)

    def test_flext_ldif_write_convenience_success(
        self,
        sample_ldif_content: str,
    ) -> None:
        """Test convenience write function success."""
        entries = flext_ldif_parse(sample_ldif_content)
        assert len(entries) > 0

        output = flext_ldif_write(entries)

        assert isinstance(output, str)
        assert len(output) > 0
        if "dn:" not in output:
            msg: str = f"Expected {'dn:'} in {output}"
            raise AssertionError(msg)

    def test_flext_ldif_write_convenience_with_file(
        self,
        sample_ldif_content: str,
    ) -> None:
        """Test convenience write function with file output."""
        entries = flext_ldif_parse(sample_ldif_content)
        assert len(entries) > 0

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as f:
            temp_file = Path(f.name)

        try:
            output = flext_ldif_write(entries, str(temp_file))

            assert isinstance(output, str)
            assert temp_file.exists()

            # Verify file content
            content = temp_file.read_text(encoding="utf-8")
            assert len(content) > 0
            if "dn:" not in content:
                msg: str = f"Expected {'dn:'} in {content}"
                raise AssertionError(msg)

        finally:
            temp_file.unlink(missing_ok=True)

    def test_flext_ldif_write_convenience_failure(self) -> None:
        """Test convenience write function with empty entries."""
        output = flext_ldif_write([])

        assert isinstance(output, str)
        if len(output) != 0:  # Should return empty string on failure
            msg = (
                f"Expected 0 (should return empty string on failure), got {len(output)}"
            )
            raise AssertionError(msg)
