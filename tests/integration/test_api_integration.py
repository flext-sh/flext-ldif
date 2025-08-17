"""Integration tests for FLEXT-LDIF API."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import FlextLdifAPI, FlextLdifConfig


class TestAPIIntegration:
    """Test API integration functionality."""

    @pytest.fixture
    def api(self) -> FlextLdifAPI:
        """Create API instance for testing."""
        return FlextLdifAPI()

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Sample LDIF content for testing."""
        return """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person
objectClass: inetOrgPerson
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
objectClass: person
objectClass: inetOrgPerson
mail: jane.smith@example.com

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit
"""

    def test_parse_and_validate_flow(
        self,
        api: FlextLdifAPI,
        sample_ldif_content: str,
    ) -> None:
        """Test complete parse and validate flow."""
        # Parse LDIF content
        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success
        assert parse_result.data is not None
        assert len(parse_result.data) == 3

        # Validate parsed entries
        validate_result = api.validate(parse_result.data)
        assert validate_result.success

    def test_parse_and_write_flow(
        self,
        api: FlextLdifAPI,
        sample_ldif_content: str,
    ) -> None:
        """Test complete parse and write flow."""
        # Parse LDIF content
        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success
        assert parse_result.data is not None

        # Write entries back to LDIF
        write_result = api.write(parse_result.data)
        assert write_result.success
        assert write_result.data is not None
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in write_result.data

    def test_file_operations(self, api: FlextLdifAPI, sample_ldif_content: str) -> None:
        """Test file read and write operations."""
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(sample_ldif_content)
            temp_file = Path(f.name)

        try:
            # Parse from file
            parse_result = api.parse_file(temp_file)
            assert parse_result.success
            assert parse_result.data is not None

            # Write to new file
            output_file = temp_file.with_suffix(".out.ldif")
            write_result = api.write_file(parse_result.data, str(output_file))
            assert write_result.success

            # Verify file was created
            assert output_file.exists()

            # Clean up
            output_file.unlink()
        finally:
            temp_file.unlink()

    def test_api_with_custom_config(self, sample_ldif_content: str) -> None:
        """Test API with custom configuration."""
        config = FlextLdifConfig(
            max_entries=10,
            strict_validation=True,
            sort_attributes=True,
        )
        api = FlextLdifAPI(config)

        parse_result = api.parse(sample_ldif_content)
        assert parse_result.success
        assert parse_result.data is not None

    def test_error_handling(self, api: FlextLdifAPI) -> None:
        """Test API error handling."""
        # Test invalid LDIF content
        invalid_ldif = "invalid ldif content without proper format"
        parse_result = api.parse(invalid_ldif)
        assert parse_result.is_failure

        # Test non-existent file
        parse_result = api.parse_file(Path("/non/existent/file.ldif"))
        assert parse_result.is_failure
